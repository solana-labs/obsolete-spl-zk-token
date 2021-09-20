// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the system program
#![cfg(feature = "test-bpf")]

use {
    bytemuck::Zeroable,
    solana_program::{program_pack::Pack, pubkey::Pubkey, system_instruction},
    solana_program_test::*,
    solana_sdk::{
        account::{Account, WritableAccount},
        clock::Epoch,
        signature::{Keypair, Signer},
        transaction::Transaction,
    },
    spl_zk_token::{self, *},
    spl_zk_token_crypto::{encryption::elgamal::ElGamal, pod::*},
};

fn program_test() -> ProgramTest {
    let mut pc = ProgramTest::new(
        "spl_zk_token",
        id(),
        processor!(processor::process_instruction),
    );

    pc.add_builtin_program(
        "spl_zk_token_crypto",
        spl_zk_token_crypto::id(),
        spl_zk_token_crypto_native::process_instruction,
    );
    pc
}

const ACCOUNT_RENT_EXEMPTION: u64 = 1_000_000_000; // go with something big to be safe

#[tokio::test]
async fn test_configure_mint_sanity() {
    let wallet_keypair = Keypair::new();
    let token_mint_keypair = Keypair::new();
    let token_account_keypair = Keypair::new();

    let (mut banks_client, payer, recent_blockhash) = program_test().start().await;

    let rent = banks_client.get_rent().await.unwrap();

    let mut transaction = Transaction::new_with_payer(
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &token_mint_keypair.pubkey(),
                rent.minimum_balance(spl_token::state::Mint::LEN),
                spl_token::state::Mint::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint(
                &spl_token::id(),
                &token_mint_keypair.pubkey(),
                &token_mint_keypair.pubkey(),
                Some(&token_mint_keypair.pubkey()),
                9,
            )
            .unwrap(),
            system_instruction::create_account(
                &payer.pubkey(),
                &token_account_keypair.pubkey(),
                rent.minimum_balance(spl_token::state::Account::LEN),
                spl_token::state::Account::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_account(
                &spl_token::id(),
                &token_account_keypair.pubkey(),
                &token_mint_keypair.pubkey(),
                &wallet_keypair.pubkey(),
            )
            .unwrap(),
        ],
        Some(&payer.pubkey()),
    );
    transaction.sign(
        &[&payer, &token_mint_keypair, &token_account_keypair],
        recent_blockhash,
    );
    banks_client.process_transaction(transaction).await.unwrap();

    let omnibus_token_address = get_omnibus_token_address(&token_mint_keypair.pubkey());
    let transfer_auditor_address = get_transfer_auditor_address(&token_mint_keypair.pubkey());

    let mut transaction = Transaction::new_with_payer(
        &[
            spl_zk_token::instruction::configure_mint_with_transfer_auditor(
                payer.pubkey(),
                token_mint_keypair.pubkey(),
                PodElGamalPK::zeroed(),
                token_mint_keypair.pubkey(),
            ),
        ],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &token_mint_keypair], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();

    // Omnibus account now exists
    let omnibus_token_account = banks_client
        .get_account(omnibus_token_address)
        .await
        .expect("get_account")
        .expect("omnibus_token_account not found");
    assert_eq!(
        omnibus_token_account.data.len(),
        spl_token::state::Account::LEN
    );
    assert_eq!(omnibus_token_account.owner, spl_token::id());

    // TransferAuditor account now exists
    let transfer_auditor_account = banks_client
        .get_account(transfer_auditor_address)
        .await
        .expect("get_account")
        .expect("transfer_auditor_account not found");

    assert_eq!(transfer_auditor_account.owner, spl_zk_token::id());
    let transfer_auditor =
        pod_from_bytes::<state::TransferAuditor>(&transfer_auditor_account.data).unwrap();
    assert_eq!(transfer_auditor.enabled, true.into());
    assert_eq!(transfer_auditor.mint, token_mint_keypair.pubkey().into());
}

#[tokio::test]
async fn test_update_account_pk() {
    let owner_keypair = Keypair::new();
    let token_mint_keypair = Keypair::new();
    let token_account_keypair = Keypair::new();
    let zk_token_account_keypair = Keypair::new();

    let (elgamal_pk, elgamal_sk) = ElGamal::keygen();

    let mut program_test = program_test();

    let mut token_mint_data = vec![0u8; spl_token::state::Mint::LEN];
    let token_mint = spl_token::state::Mint {
        supply: 123456789,
        decimals: 9,
        is_initialized: true,
        ..spl_token::state::Mint::default()
    };
    Pack::pack(token_mint, &mut token_mint_data).unwrap();
    let mint_account = Account::create(
        ACCOUNT_RENT_EXEMPTION,
        token_mint_data,
        spl_token::id(),
        false,
        Epoch::default(),
    );
    program_test.add_account(token_mint_keypair.pubkey(), mint_account);

    let mut token_account_data = vec![0u8; spl_token::state::Account::LEN];
    let token_account_state = spl_token::state::Account {
        mint: token_mint_keypair.pubkey(),
        owner: owner_keypair.pubkey(),
        state: spl_token::state::AccountState::Initialized,
        ..spl_token::state::Account::default()
    };
    Pack::pack(token_account_state, &mut token_account_data).unwrap();
    let token_account = Account::create(
        ACCOUNT_RENT_EXEMPTION,
        token_account_data,
        spl_token::id(),
        false,
        Epoch::default(),
    );

    let available_balance = 123;
    let available_balance_ct = elgamal_pk.encrypt(available_balance);
    let zk_token_account_state = spl_zk_token::state::ConfidentialAccount {
        mint: token_account_state.mint.into(),
        token_account: token_account_keypair.pubkey().into(),
        elgamal_pk: elgamal_pk.into(),
        available_balance: available_balance_ct.into(),
        ..spl_zk_token::state::ConfidentialAccount::zeroed()
    };
    let zk_token_account = Account::create(
        ACCOUNT_RENT_EXEMPTION,
        pod_bytes_of(&zk_token_account_state).to_vec(),
        id(),
        false,
        Epoch::default(),
    );

    program_test.add_account(token_account_keypair.pubkey(), token_account);
    program_test.add_account(zk_token_account_keypair.pubkey(), zk_token_account);

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let (new_elgamal_pk, new_elgamal_sk) = ElGamal::keygen();

    let data = spl_zk_token::instruction::UpdateAccountPkData::new(
        available_balance,
        available_balance_ct,
        elgamal_pk,
        &elgamal_sk,
        new_elgamal_pk,
        &new_elgamal_sk,
    );

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::update_account_pk(
            zk_token_account_keypair.pubkey(),
            token_account_keypair.pubkey(),
            owner_keypair.pubkey(),
            &[],
            data,
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner_keypair], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}
