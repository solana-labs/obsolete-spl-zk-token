// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the system program
#![cfg(feature = "test-bpf")]

use solana_program::{program_pack::Pack, pubkey::Pubkey, system_instruction};
use solana_program_test::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_zk_token::{pod::*, *};

fn program_test() -> ProgramTest {
    let pc = ProgramTest::new(
        "spl_zk_token",
        id(),
        processor!(processor::process_instruction),
    );
    pc
}

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
                ElGamalPK::default(),
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
