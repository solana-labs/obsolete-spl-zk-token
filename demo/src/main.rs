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
    solana_zk_token_sdk::encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        elgamal::*,
    },
    spl_zk_token::pod::*,
    std::{convert::TryInto, process::exit, sync::Arc},
};

struct Config {
    commitment_config: CommitmentConfig,
    default_signer: Box<dyn Signer>,
    json_rpc_url: String,
    verbose: bool,
}

fn get_zk_token_auditor(
    rpc_client: &RpcClient,
    token_mint: &Pubkey,
) -> client_error::Result<ElGamalPubkey> {
    let zk_auditor = spl_zk_token::get_zk_mint_address(token_mint);
    let account = rpc_client.get_account(&zk_auditor)?;

    spl_zk_token::state::ZkMint::from_bytes(&account.data)
        .map(|zk_mint| {
            zk_mint
                .auditor
                .auditor_pk
                .try_into()
                .expect("valid auditor_pk")
        })
        .ok_or_else(|| client_error::ClientError {
            request: None,
            kind: client_error::ClientErrorKind::Custom(format!(
                "Invalid account data: {}",
                zk_auditor,
            )),
        })
}

fn get_zk_token_state(
    rpc_client: &RpcClient,
    zk_token_account: &Pubkey,
) -> client_error::Result<spl_zk_token::state::ZkAccount> {
    let account = rpc_client.get_account(zk_token_account)?;

    spl_zk_token::state::ZkAccount::from_bytes(&account.data)
        .cloned()
        .ok_or_else(|| client_error::ClientError {
            request: None,
            kind: client_error::ClientErrorKind::Custom(format!(
                "Invalid account data: {}",
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
    /* decryptable_available_balance: */ AeCiphertext,
)> {
    get_zk_token_state(rpc_client, zk_token_account).map(|zk_token_state| {
        (
            zk_token_state.pending_balance.try_into().unwrap(),
            zk_token_state.available_balance.try_into().unwrap(),
            zk_token_state
                .decryptable_available_balance
                .try_into()
                .unwrap(),
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

    #[allow(deprecated)]
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
    let token_mint = Keypair::new();

    let token_account_a = Keypair::new();
    let elgamal_keypair_a = ElGamalKeypair::new_rand();
    let elgamal_pk_a = elgamal_keypair_a.public;

    let zk_token_account_a =
        spl_zk_token::get_zk_token_address(&token_mint.pubkey(), &token_account_a.pubkey());

    let ae_key_a = AeKey::new(&token_account_a, &zk_token_account_a).unwrap();

    let token_account_b = Keypair::new();
    let elgamal_keypair_b = ElGamalKeypair::new_rand();
    let elgamal_pk_b = elgamal_keypair_b.public;

    let zk_token_account_b =
        spl_zk_token::get_zk_token_address(&token_mint.pubkey(), &token_account_b.pubkey());

    let ae_key_b = AeKey::new(&token_account_b, &zk_token_account_b).unwrap();

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
            spl_zk_token::instruction::configure_mint(
                payer.pubkey(),
                token_mint.pubkey(),
                None,
                &[],
                None,
            ),
        ],
        &[payer, &token_mint],
    )?;

    let auditor_pk = get_zk_token_auditor(rpc_client, &token_mint.pubkey())?;
    let mint_amount = 100;
    let omnibus_token_account = spl_zk_token::get_omnibus_token_address(&token_mint.pubkey());

    for (token_account, elgamal_pk, ae_key) in [
        (&token_account_a, &elgamal_pk_a, &ae_key_a),
        (&token_account_b, &elgamal_pk_b, &ae_key_b),
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

        let zk_token_account =
            spl_zk_token::get_zk_token_address(&token_mint.pubkey(), &token_account.pubkey());

        // encrypt zero using authenticated encryption
        let ae_ciphertext = ae_key.encrypt(0_u64);

        send(
            rpc_client,
            &format!(
                "Configuring confidential token account {}",
                zk_token_account
            ),
            &spl_zk_token::instruction::configure_account(
                payer.pubkey(),
                zk_token_account,
                *elgamal_pk,
                ae_ciphertext,
                token_account.pubkey(),
                payer.pubkey(),
                &[],
            ),
            &[payer],
        )?;
        send(
            rpc_client,
            &format!(
                "Enabling credits on confidential token account {}",
                zk_token_account
            ),
            &spl_zk_token::instruction::enable_balance_credits(
                zk_token_account,
                token_account.pubkey(),
                &token_mint.pubkey(),
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
            token_mint.pubkey(),
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

    // `incoming_transfer_count` should be set to incremented to 1
    assert_eq!(
        get_zk_token_state(rpc_client, &zk_token_account_a)?.pending_balance_credit_counter,
        1.into(),
    );

    send(
        rpc_client,
        &format!("Applying pending balance for {}", zk_token_account_a),
        &spl_zk_token::instruction::apply_pending_balance(
            zk_token_account_a,
            token_account_a.pubkey(),
            payer.pubkey(),
            &[],
            1,                             // expected `incoming_transfer_count`
            ae_key_a.encrypt(mint_amount), // update AE ciphertext with mint amount
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

    let (pending_balance_ct_a, available_balance_ct_a, current_balance_ct_a) =
        get_zk_token_balance(rpc_client, &zk_token_account_a)?;
    assert_eq!(pending_balance_ct_a, ElGamalCiphertext::default());

    // Client should use `decryptable_available_balance` to recover the amount
    assert_eq!(
        current_balance_ct_a.decrypt(&ae_key_a).unwrap() as u64,
        current_balance_a
    );

    assert_eq!(
        get_zk_token_state(rpc_client, &zk_token_account_a)?.actual_pending_balance_credit_counter,
        1.into()
    );

    let transfer_proof_data = spl_zk_token::instruction::TransferData::new(
        mint_amount,
        (current_balance_a, &available_balance_ct_a),
        &elgamal_keypair_a,
        (&elgamal_pk_b, &auditor_pk),
    )
    .unwrap();

    // Extract transfer amount from `transfer_data` and demonstrate decrypting using
    // `elgamal_sk_a` and `elgamal_sk_b`
    assert_eq!(
        transfer_proof_data
            .decrypt_amount(
                spl_zk_token::instruction::Role::Source,
                &elgamal_keypair_a.secret,
            )
            .unwrap() as u64,
        mint_amount,
    );

    assert_eq!(
        transfer_proof_data
            .decrypt_amount(
                spl_zk_token::instruction::Role::Dest,
                &elgamal_keypair_b.secret,
            )
            .unwrap() as u64,
        mint_amount,
    );

    send(
        rpc_client,
        &format!(
            "Transferring {} confidentially from {} to {}",
            current_balance_a, zk_token_account_a, zk_token_account_b
        ),
        &spl_zk_token::instruction::transfer(
            zk_token_account_a,
            token_account_a.pubkey(),
            zk_token_account_b,
            token_account_b.pubkey(),
            &token_mint.pubkey(),
            payer.pubkey(),
            &[],
            ae_key_a.encrypt(0_u64),
            &transfer_proof_data,
        ),
        &[payer],
    )?;

    send(
        rpc_client,
        &format!("Applying pending balance for {}", zk_token_account_b),
        &spl_zk_token::instruction::apply_pending_balance(
            zk_token_account_b,
            token_account_b.pubkey(),
            payer.pubkey(),
            &[],
            1,
            ae_key_b.encrypt(100_u64),
        ),
        &[payer],
    )?;

    current_balance_b += current_balance_a;
    current_balance_a -= current_balance_a;

    let (_pending_balance_ct_a, _available_balance_ct_a, current_balance_ct_a) =
        get_zk_token_balance(rpc_client, &zk_token_account_a)?;

    let (_pending_balance_ct_b, _available_balance_ct_b, current_balance_ct_b) =
        get_zk_token_balance(rpc_client, &zk_token_account_b)?;

    assert_eq!(
        current_balance_ct_a.decrypt(&ae_key_a).unwrap() as u64,
        current_balance_a
    );

    assert_eq!(
        current_balance_ct_b.decrypt(&ae_key_b).unwrap() as u64,
        current_balance_b
    );

    let (_pending_balance_ct_b, available_balance_ct_b, _current_balance_ct_b) =
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
            ae_key_b.encrypt(0_u64),
            &spl_zk_token::instruction::WithdrawData::new(
                current_balance_b,
                &elgamal_keypair_b,
                current_balance_b,
                &available_balance_ct_b,
            )
            .unwrap(),
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

    let (_pending_balance_ct_a, available_balance_ct_a, current_balance_ct_a) =
        get_zk_token_balance(rpc_client, &zk_token_account_a)?;

    let (_pending_balance_ct_b, _available_balance_ct_b, current_balance_ct_b) =
        get_zk_token_balance(rpc_client, &zk_token_account_b)?;

    assert_eq!(
        current_balance_ct_a.decrypt(&ae_key_a).unwrap() as u64,
        current_balance_a
    );

    assert_eq!(
        current_balance_ct_b.decrypt(&ae_key_b).unwrap() as u64,
        current_balance_b
    );

    // Close account A
    let close_account_proof_data = spl_zk_token::instruction::CloseAccountData::new(
        &elgamal_keypair_a,
        &available_balance_ct_a,
    )
    .unwrap();

    send(
        rpc_client,
        &format!("Closing confidential token account {}", zk_token_account_a),
        &spl_zk_token::instruction::close_account(
            zk_token_account_a,
            token_account_a.pubkey(),
            payer.pubkey(),
            payer.pubkey(),
            &[],
            &close_account_proof_data,
        ),
        &[payer],
    )?;

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
    use {super::*, solana_test_validator::*};

    #[test]
    #[ignore]
    fn test_demo() {
        let (test_validator, payer) = TestValidatorGenesis::default()
            .add_program("spl_zk_token", spl_zk_token::id())
            .start();

        let rpc_client = test_validator.get_rpc_client();
        assert!(matches!(process_demo(&rpc_client, &payer), Ok(_)));
    }
}
