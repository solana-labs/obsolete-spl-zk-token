// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the system program
#![cfg(feature = "test-bpf")]

use {
    bytemuck::Zeroable,
    solana_program::{program_pack::Pack, pubkey::Pubkey},
    solana_program_test::*,
    solana_sdk::{
        account::{Account, WritableAccount},
        clock::Epoch,
        signature::{Keypair, Signer},
        transaction::Transaction,
    },
    spl_zk_token::{self, *},
    spl_zk_token_crypto::{
        encryption::elgamal::{ElGamal, ElGamalCT, ElGamalPK},
        pod::*,
    },
};

fn program_test() -> ProgramTest {
    ProgramTest::new(
        "spl_zk_token",
        id(),
        processor!(processor::process_instruction),
    )
}
// TODO: Use this `program_test()` implementation once Solana 1.7.13 ships
/*
fn program_test() -> ProgramTest {
    let mut pc = ProgramTest::new(
        "spl_zk_token",
        id(),
        processor!(processor::process_instruction),
    );

    pc.add_builtin_program(
        "spl_zk_token_crypto",
        spl_zk_token_crypto::id(),
        spl_zk_token_proof::process_instruction,
    );
    pc
}
*/

const ACCOUNT_RENT_EXEMPTION: u64 = 1_000_000_000; // go with something big to be safe

fn add_token_mint_account(
    program_test: &mut ProgramTest,
    freeze_authority: Option<Pubkey>,
) -> Pubkey {
    let token_mint_keypair = Keypair::new();

    let mut token_mint_data = vec![0u8; spl_token::state::Mint::LEN];
    let token_mint = spl_token::state::Mint {
        supply: 123456789,
        decimals: 0,
        is_initialized: true,
        freeze_authority: freeze_authority.into(),
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

    token_mint_keypair.pubkey()
}

fn add_token_account(
    program_test: &mut ProgramTest,
    mint: Pubkey,
    owner: Pubkey,
    balance: u64,
) -> Pubkey {
    let token_account_keypair = Keypair::new();

    let mut token_account_data = vec![0u8; spl_token::state::Account::LEN];
    let token_account_state = spl_token::state::Account {
        mint,
        owner,
        amount: balance,
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
    program_test.add_account(token_account_keypair.pubkey(), token_account);
    token_account_keypair.pubkey()
}

fn add_zk_token_account(
    program_test: &mut ProgramTest,
    mint: Pubkey,
    token_account: Pubkey,
    elgamal_pk: ElGamalPK,
    balance: ElGamalCT,
) -> Pubkey {
    let zk_token_account_keypair = Keypair::new();

    let zk_token_account_state = spl_zk_token::state::ConfidentialAccount {
        mint: mint.into(),
        token_account: token_account.into(),
        elgamal_pk: elgamal_pk.into(),
        available_balance: balance.into(),
        ..spl_zk_token::state::ConfidentialAccount::zeroed()
    };
    let zk_token_account = Account::create(
        ACCOUNT_RENT_EXEMPTION,
        pod_bytes_of(&zk_token_account_state).to_vec(),
        id(),
        false,
        Epoch::default(),
    );

    program_test.add_account(zk_token_account_keypair.pubkey(), zk_token_account);

    zk_token_account_keypair.pubkey()
}

#[tokio::test]
async fn test_configure_mint() {
    let owner_keypair = Keypair::new();
    let freeze_authority = Keypair::new();
    let transfer_auditor_elgamal_pk = ElGamal::keygen().0;

    let mut program_test = program_test();
    let mint = add_token_mint_account(&mut program_test, Some(freeze_authority.pubkey()));
    let _token_account = add_token_account(&mut program_test, mint, owner_keypair.pubkey(), 123);

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let omnibus_token_address = get_omnibus_token_address(&mint);
    let transfer_auditor_address = get_transfer_auditor_address(&mint);

    // Failure case: cannot configure the zk mint without the freeze authority signing
    let mut transaction = Transaction::new_with_payer(
        &[spl_zk_token::instruction::configure_mint(
            payer.pubkey(),
            mint,
        )],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap_err();

    // Success case: configure the zk mint
    let mut transaction = Transaction::new_with_payer(
        &[
            spl_zk_token::instruction::configure_mint_with_transfer_auditor(
                payer.pubkey(),
                mint,
                transfer_auditor_elgamal_pk.into(),
                freeze_authority.pubkey(),
            ),
        ],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &freeze_authority], recent_blockhash);
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
    assert_eq!(transfer_auditor.mint, mint.into());
}

#[tokio::test]
#[ignore] // TODO: remove once Solana 1.7.13 ships
async fn test_update_account_pk() {
    let owner_keypair = Keypair::new();

    let (elgamal_pk, elgamal_sk) = ElGamal::keygen();

    let mut program_test = program_test();

    let mint = add_token_mint_account(&mut program_test, None);
    let token_account = add_token_account(&mut program_test, mint, owner_keypair.pubkey(), 123);

    let zk_available_balance = 123;
    let zk_available_balance_ct = elgamal_pk.encrypt(zk_available_balance);
    let zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        token_account,
        elgamal_pk,
        zk_available_balance_ct,
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let (new_elgamal_pk, new_elgamal_sk) = ElGamal::keygen();

    let data = spl_zk_token::instruction::UpdateAccountPkData::new(
        zk_available_balance,
        zk_available_balance_ct,
        elgamal_pk,
        &elgamal_sk,
        new_elgamal_pk,
        &new_elgamal_sk,
    );

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::update_account_pk(
            zk_token_account,
            token_account,
            owner_keypair.pubkey(),
            &[],
            data,
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner_keypair], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn test_create_account() {
    todo!()
}

#[tokio::test]
#[ignore]
async fn test_close_account() {
    todo!()
}

#[tokio::test]
#[ignore]
async fn test_deposit() {
    todo!()
}

#[tokio::test]
#[ignore]
async fn test_withdraw() {
    todo!()
}
