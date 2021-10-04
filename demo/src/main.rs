use {
    clap::{crate_description, crate_name, crate_version, App, Arg},
    solana_clap_utils::{
        input_validators::{is_url_or_moniker, is_valid_signer, normalize_to_url_if_moniker},
        keypair::DefaultSigner,
    },
    solana_client::{client_error, rpc_client::RpcClient},
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        instruction::Instruction,
        message::Message,
        program_pack::Pack,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    },
    spl_zk_token::pod::*,
    spl_zk_token_sdk::encryption::{discrete_log, elgamal::*},
    std::{convert::TryInto, process::exit, sync::Arc},
};

struct Config {
    commitment_config: CommitmentConfig,
    default_signer: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
}

fn get_zk_token_transfer_auditor(
    rpc_client: &RpcClient,
    token_mint: &Pubkey,
) -> client_error::Result<ElGamalPubkey> {
    let zk_transfer_auditor = spl_zk_token::get_transfer_auditor_address(token_mint);
    let account = rpc_client.get_account(&zk_transfer_auditor)?;

    spl_zk_token::state::TransferAuditor::from_bytes(&account.data)
        .map(|transfer_auditor| {
            transfer_auditor
                .elgamal_pk
                .try_into()
                .expect("valid elgamal_pk")
        })
        .ok_or_else(|| client_error::ClientError {
            request: None,
            kind: client_error::ClientErrorKind::Custom(format!(
                "Invalid acccount data: {}",
                zk_transfer_auditor,
            )),
        })
}

fn get_zk_token_state(
    rpc_client: &RpcClient,
    zk_token_account: &Pubkey,
) -> client_error::Result<spl_zk_token::state::ConfidentialAccount> {
    let account = rpc_client.get_account(zk_token_account)?;

    spl_zk_token::state::ConfidentialAccount::from_bytes(&account.data)
        .cloned()
        .ok_or_else(|| client_error::ClientError {
            request: None,
            kind: client_error::ClientErrorKind::Custom(format!(
                "Invalid acccount data: {}",
                zk_token_account
            )),
        })
}

fn get_zk_token_balance(
    rpc_client: &RpcClient,
    zk_token_account: &Pubkey,
) -> client_error::Result<(
    /* pending_balance: */ ElGamalCiphertext,
    /* available_balance: */ ElGamalCiphertext,
)> {
    get_zk_token_state(rpc_client, zk_token_account).map(|zk_token_state| {
        (
            zk_token_state.pending_balance.try_into().unwrap(),
            zk_token_state.available_balance.try_into().unwrap(),
        )
    })
}

fn send(
    rpc_client: &RpcClient,
    msg: &str,
    instructions: &[Instruction],
    signers: &[&dyn Signer],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("==> {}", msg);
    let mut transaction =
        Transaction::new_unsigned(Message::new(instructions, Some(&signers[0].pubkey())));

    let (recent_blockhash, _fee_calculator) = rpc_client
        .get_recent_blockhash()
        .map_err(|err| format!("error: unable to get recent blockhash: {}", err))?;

    transaction
        .try_sign(&signers.to_vec(), recent_blockhash)
        .map_err(|err| format!("error: failed to sign transaction: {}", err))?;

    let signature = rpc_client
        .send_and_confirm_transaction_with_spinner(&transaction)
        .map_err(|err| format!("error: send transaction: {}", err))?;
    println!("Signature: {}", signature);
    Ok(())
}

fn process_demo(
    rpc_client: &RpcClient,
    payer: &dyn Signer,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("==> Precomputing discrete log data for decryption (~300kb)");
    let decryption_data = discrete_log::decode_u32_precomputation_for_G(); // TODO: Move to build time

    let token_mint = Keypair::new();

    let token_account_a = Keypair::new();
    let (elgamal_pk_a, elgamal_sk_a) = ElGamal::new();

    let zk_token_account_a = spl_zk_token::get_confidential_token_address(
        &token_mint.pubkey(),
        &token_account_a.pubkey(),
    );

    let token_account_b = Keypair::new();
    let (elgamal_pk_b, elgamal_sk_b) = ElGamal::new();
    let zk_token_account_b = spl_zk_token::get_confidential_token_address(
        &token_mint.pubkey(),
        &token_account_b.pubkey(),
    );

    let mint_minimum_balance_for_rent_exemption = rpc_client
        .get_minimum_balance_for_rent_exemption(spl_token::state::Mint::get_packed_len())?;
    let account_minimum_balance_for_rent_exemption = rpc_client
        .get_minimum_balance_for_rent_exemption(spl_token::state::Account::get_packed_len())?;

    send(
        rpc_client,
        &format!("Creating token mint: {}", token_mint.pubkey()),
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &token_mint.pubkey(),
                mint_minimum_balance_for_rent_exemption,
                spl_token::state::Mint::get_packed_len() as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint(
                &spl_token::id(),
                &token_mint.pubkey(),
                &payer.pubkey(),
                None,
                0,
            )?,
            spl_zk_token::instruction::configure_mint(payer.pubkey(), token_mint.pubkey()),
        ],
        &[payer, &token_mint],
    )?;

    let auditor_elgamal_pk = get_zk_token_transfer_auditor(rpc_client, &token_mint.pubkey())?;
    let mint_amount = 100;
    let omnibus_token_account = spl_zk_token::get_omnibus_token_address(&token_mint.pubkey());

    for (token_account, elgamal_pk) in [
        (&token_account_a, &elgamal_pk_a),
        (&token_account_b, &elgamal_pk_b),
    ] {
        send(
            rpc_client,
            &format!(
                "Creating token account with {} tokens: {}",
                mint_amount,
                token_account.pubkey(),
            ),
            &[
                system_instruction::create_account(
                    &payer.pubkey(),
                    &token_account.pubkey(),
                    account_minimum_balance_for_rent_exemption,
                    spl_token::state::Account::get_packed_len() as u64,
                    &spl_token::id(),
                ),
                spl_token::instruction::initialize_account(
                    &spl_token::id(),
                    &token_account.pubkey(),
                    &token_mint.pubkey(),
                    &payer.pubkey(),
                )?,
                spl_token::instruction::mint_to(
                    &spl_token::id(),
                    &token_mint.pubkey(),
                    &token_account.pubkey(),
                    &payer.pubkey(),
                    &[],
                    mint_amount,
                )?,
            ],
            &[payer, token_account, payer],
        )?;
        let zk_token_account = spl_zk_token::get_confidential_token_address(
            &token_mint.pubkey(),
            &token_account.pubkey(),
        );
        send(
            rpc_client,
            &format!("Creating confidential token account {}", zk_token_account),
            &spl_zk_token::instruction::create_account(
                payer.pubkey(),
                zk_token_account,
                *elgamal_pk,
                token_account.pubkey(),
                payer.pubkey(),
                &[],
            ),
            &[payer],
        )?;

        assert_eq!(
            rpc_client
                .get_token_account_balance(&token_account.pubkey())?
                .amount,
            mint_amount.to_string()
        );
    }

    let mut current_balance_a = 0;
    let mut current_balance_b = 0;

    send(
        rpc_client,
        &format!(
            "Depositing {} from {} to {}",
            mint_amount,
            token_account_a.pubkey(),
            zk_token_account_a
        ),
        &spl_zk_token::instruction::deposit(
            token_account_a.pubkey(),
            &token_mint.pubkey(),
            zk_token_account_a,
            token_account_a.pubkey(),
            payer.pubkey(),
            &[],
            mint_amount,
            0,
        ),
        &[payer],
    )?;

    current_balance_a += mint_amount;

    send(
        rpc_client,
        &format!("Applying pending balance for {}", zk_token_account_a),
        &spl_zk_token::instruction::apply_pending_balance(
            zk_token_account_a,
            token_account_a.pubkey(),
            payer.pubkey(),
            &[],
        ),
        &[payer],
    )?;

    assert_eq!(
        rpc_client
            .get_token_account_balance(&token_account_a.pubkey())?
            .amount,
        "0",
    );
    assert_eq!(
        rpc_client
            .get_token_account_balance(&omnibus_token_account)?
            .amount,
        "100",
    );

    let (pending_balance_ct_a, current_balance_ct_a) =
        get_zk_token_balance(rpc_client, &zk_token_account_a)?;
    assert_eq!(pending_balance_ct_a, ElGamalCiphertext::default());

    // NOTE: account balance ciphertexts can still be decrypted as long as the balance is < 2^32
    assert_eq!(
        current_balance_ct_a
            .decrypt_u32_online(&elgamal_sk_a, &decryption_data)
            .unwrap() as u64,
        current_balance_a
    );

    let transfer_data = spl_zk_token::instruction::TransferData::new(
        mint_amount,
        current_balance_a,
        current_balance_ct_a,
        elgamal_pk_a,
        &elgamal_sk_a,
        elgamal_pk_b,
        auditor_elgamal_pk,
    );

    // TODO: Extract transfer amount from `transfer_data` and demonstrate decrypting using
    // `elgamal_sk_a` and `elgamal_sk_b`
    let source_ciphertext = transfer_data.source_ciphertext();
    assert_eq!(
        source_ciphertext.unwrap()
            .decrypt_u32_online(&elgamal_sk_a, &decryption_data)
            .unwrap() as u64,
        mint_amount,
    );

    let dest_ciphertext = transfer_data.dest_ciphertext();
    assert_eq!(
        dest_ciphertext.unwrap()
            .decrypt_u32_online(&elgamal_sk_b, &decryption_data)
            .unwrap() as u64,
        mint_amount,
    );

    let (mut transfer_range_proof, transfer_validity_proof) = spl_zk_token::instruction::transfer(
        zk_token_account_a,
        token_account_a.pubkey(),
        zk_token_account_b,
        token_account_b.pubkey(),
        &token_mint.pubkey(),
        payer.pubkey(),
        &[],
        transfer_data,
    );

    transfer_range_proof.extend(transfer_validity_proof);
    send(
        rpc_client,
        &format!(
            "Transferring {} confidentially from {} to {}",
            current_balance_a, zk_token_account_a, zk_token_account_b
        ),
        &transfer_range_proof,
        &[payer],
    )?;

    /*
    send(
        rpc_client,
        &format!(
            "Transferring (Range Proof) {} from {} to {}",
            current_balance_a, zk_token_account_a, zk_token_account_b
        ),
        &transfer_range_proof,
        &[payer],
    )?;
    send(
        rpc_client,
        &format!(
            "Transferring (Validity Proof) {} from {} to {}",
            current_balance_a, zk_token_account_a, zk_token_account_b
        ),
        &transfer_validity_proof,
        &[payer],
    )?;
    */

    send(
        rpc_client,
        &format!("Applying pending balance for {}", zk_token_account_b),
        &spl_zk_token::instruction::apply_pending_balance(
            zk_token_account_b,
            token_account_b.pubkey(),
            payer.pubkey(),
            &[],
        ),
        &[payer],
    )?;

    current_balance_b += current_balance_a;
    current_balance_a -= current_balance_a;

    let (_pending_balance_ct_a, current_balance_ct_a) =
        get_zk_token_balance(rpc_client, &zk_token_account_a)?;

    let (_pending_balance_ct_b, current_balance_ct_b) =
        get_zk_token_balance(rpc_client, &zk_token_account_b)?;

    assert_eq!(
        current_balance_ct_a
            .decrypt_u32_online(&elgamal_sk_a, &decryption_data)
            .unwrap() as u64,
        current_balance_a
    );

    assert_eq!(
        current_balance_ct_b
            .decrypt_u32_online(&elgamal_sk_b, &decryption_data)
            .unwrap() as u64,
        current_balance_b
    );

    let (_pending_balance_ct_b, current_balance_ct_b) =
        get_zk_token_balance(rpc_client, &zk_token_account_b)?;
    send(
        rpc_client,
        &format!(
            "Withdrawing {} from {} to {}",
            current_balance_b,
            token_account_b.pubkey(),
            zk_token_account_b
        ),
        &spl_zk_token::instruction::withdraw(
            zk_token_account_b,
            token_account_b.pubkey(),
            token_account_b.pubkey(),
            &token_mint.pubkey(),
            payer.pubkey(),
            &[],
            current_balance_b,
            0,
            spl_zk_token::instruction::WithdrawData::new(
                current_balance_b,
                elgamal_pk_a,
                &elgamal_sk_b,
                current_balance_b,
                current_balance_ct_b,
            ),
        ),
        &[payer],
    )?;

    current_balance_b -= current_balance_b;

    // Final balance sanity checks
    assert_eq!(
        rpc_client
            .get_token_account_balance(&token_account_b.pubkey())?
            .amount,
        (mint_amount * 2).to_string(),
    );
    assert_eq!(
        rpc_client
            .get_token_account_balance(&omnibus_token_account)?
            .amount,
        "0",
    );
    assert_eq!(current_balance_a, 0);
    assert_eq!(current_balance_b, 0);

    let (_pending_balance_ct_a, current_balance_ct_a) =
        get_zk_token_balance(rpc_client, &zk_token_account_a)?;

    let (_pending_balance_ct_b, current_balance_ct_b) =
        get_zk_token_balance(rpc_client, &zk_token_account_b)?;

    assert_eq!(
        current_balance_ct_a
            .decrypt_u32_online(&elgamal_sk_a, &decryption_data)
            .unwrap() as u64,
        current_balance_a
    );

    assert_eq!(
        current_balance_ct_b
            .decrypt_u32_online(&elgamal_sk_b, &decryption_data)
            .unwrap() as u64,
        current_balance_b
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("keypair")
                .long("keypair")
                .value_name("KEYPAIR")
                .validator(is_valid_signer)
                .takes_value(true)
                .global(true)
                .help("Filepath or URL to a keypair [default: client keypair]"),
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .short("u")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .global(true)
                .validator(is_url_or_moniker)
                .help("JSON RPC URL for the cluster [default: value from configuration file]"),
        )
        .get_matches();

    let mut wallet_manager: Option<Arc<RemoteWalletManager>> = None;

    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };

        let default_signer = DefaultSigner::new(
            "keypair",
            matches
                .value_of(&"keypair")
                .map(|s| s.to_string())
                .unwrap_or_else(|| cli_config.keypair_path.clone()),
        );

        Config {
            json_rpc_url: normalize_to_url_if_moniker(
                matches
                    .value_of("json_rpc_url")
                    .unwrap_or(&cli_config.json_rpc_url)
                    .to_string(),
            ),
            default_signer: default_signer
                .signer_from_path(&matches, &mut wallet_manager)
                .unwrap_or_else(|err| {
                    eprintln!("error: {}", err);
                    exit(1);
                }),
            verbose: matches.is_present("verbose"),
            commitment_config: CommitmentConfig::confirmed(),
        }
    };
    solana_logger::setup_with_default("solana=info");

    if config.verbose {
        println!("JSON RPC URL: {}", config.json_rpc_url);
    }
    let rpc_client =
        RpcClient::new_with_commitment(config.json_rpc_url.clone(), config.commitment_config);

    process_demo(&rpc_client, config.default_signer.as_ref()).unwrap_or_else(|err| {
        eprintln!("error: {}", err);
        exit(1);
    });

    Ok(())
}

#[cfg(test)]
mod test {
    use {super::*, solana_validator::test_validator::*};

    #[test]
    #[ignore]
    fn test_demo() {
        let (test_validator, payer) = TestValidatorGenesis::default()
            .add_program("spl_zk_token", spl_zk_token::id())
            .start();

        let (rpc_client, _recent_blockhash, _fee_calculator) = test_validator.rpc_client();
        assert!(matches!(process_demo(&rpc_client, &payer), Ok(_)));
    }
}
