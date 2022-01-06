#![allow(unused_imports)] // Remove once the `twoxtx` feature no longer exists
#![allow(dead_code)] // Remove once the `twoxtx` feature no longer exists
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
    solana_zk_token_sdk::encryption::{
        auth_encryption::AeCiphertext,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    spl_zk_token::{self, pod::*, state::Auditor, *},
};
#[cfg(feature = "test-bpf")]
use {
    solana_zk_token_sdk::encryption::pedersen::PedersenOpening,
    std::{borrow::Borrow, convert::TryInto},
};

fn program_test() -> ProgramTest {
    ProgramTest::new(
        "spl_zk_token",
        id(),
        processor!(processor::process_instruction),
    )
}

const ACCOUNT_RENT_EXEMPTION: u64 = 1_000_000_000; // go with something big to be safe
const DECIMALS: u8 = 0;

fn assert_transaction_size(_transaction: &Transaction) {
    // TODO: Remove this function once https://github.com/solana-labs/solana/pull/20297 ships
    /*
    let serialized = bincode::serialize(&transaction).unwrap();
    assert!(
        serialized.len() < solana_sdk::packet::PACKET_DATA_SIZE,
        "{} too big; max {}",
        serialized.len(),
        solana_sdk::packet::PACKET_DATA_SIZE
    );
    */
}

fn add_token_mint_account(
    program_test: &mut ProgramTest,
    freeze_authority: Option<Pubkey>,
) -> Pubkey {
    let token_mint_keypair = Keypair::new();

    let mut token_mint_data = vec![0u8; spl_token::state::Mint::LEN];
    let token_mint = spl_token::state::Mint {
        supply: 123456789,
        decimals: DECIMALS,
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

fn add_token_account_with_address(
    program_test: &mut ProgramTest,
    token_address: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    balance: u64,
) {
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
    program_test.add_account(token_address, token_account);
}

fn add_token_account(
    program_test: &mut ProgramTest,
    mint: Pubkey,
    owner: Pubkey,
    balance: u64,
) -> Pubkey {
    let token_account_keypair = Keypair::new();
    add_token_account_with_address(
        program_test,
        token_account_keypair.pubkey(),
        mint,
        owner,
        balance,
    );
    token_account_keypair.pubkey()
}

#[cfg(feature = "test-bpf")]
fn add_omnibus_token_account(program_test: &mut ProgramTest, mint: Pubkey, balance: u64) -> Pubkey {
    let omnibus_token_address = get_omnibus_token_address(&mint);
    add_token_account_with_address(
        program_test,
        omnibus_token_address,
        mint,
        omnibus_token_address,
        balance,
    );
    omnibus_token_address
}

fn add_zk_mint_account(
    program_test: &mut ProgramTest,
    mint: Pubkey,
    elgamal_pk: Option<ElGamalPubkey>,
) -> Pubkey {
    let zk_mint_address = get_zk_mint_address(&mint);

    let zk_mint_state = spl_zk_token::state::ZkMint {
        mint,
        auditor: Auditor {
            enable_balance_credits_authority: Pubkey::default(),
            auditor_pk: elgamal_pk.unwrap_or_default().into(),
        },
    };
    let zk_mint_account = Account::create(
        ACCOUNT_RENT_EXEMPTION,
        bytemuck::bytes_of(&zk_mint_state).to_vec(),
        id(),
        false,
        Epoch::default(),
    );

    program_test.add_account(zk_mint_address, zk_mint_account);
    zk_mint_address
}

fn add_zk_token_account(
    program_test: &mut ProgramTest,
    mint: Pubkey,
    token_account: Pubkey,
    elgamal_pk: ElGamalPubkey,
    available_balance: ElGamalCiphertext,
) -> Pubkey {
    let zk_token_address = get_zk_token_address(&mint, &token_account);

    let zk_token_account_state = spl_zk_token::state::ZkAccount {
        mint,
        token_account,
        elgamal_pk: elgamal_pk.into(),
        available_balance: available_balance.into(),
        allow_balance_credits: true.into(),
        ..spl_zk_token::state::ZkAccount::zeroed()
    };
    let zk_token_account = Account::create(
        ACCOUNT_RENT_EXEMPTION,
        bytemuck::bytes_of(&zk_token_account_state).to_vec(),
        id(),
        false,
        Epoch::default(),
    );

    program_test.add_account(zk_token_address, zk_token_account);
    zk_token_address
}

#[cfg(feature = "test-bpf")]
async fn get_token_balance(banks_client: &mut BanksClient, token_address: Pubkey) -> u64 {
    let token_account = banks_client
        .get_account(token_address)
        .await
        .expect("get_account")
        .expect("omnibus_token_account not found");
    assert_eq!(token_account.data.len(), spl_token::state::Account::LEN);
    assert_eq!(token_account.owner, spl_token::id());
    let state = spl_token::state::Account::unpack(&token_account.data.borrow()).expect("unpack");
    state.amount
}

async fn get_zk_token_state(
    banks_client: &mut BanksClient,
    zk_token_account: Pubkey,
) -> spl_zk_token::state::ZkAccount {
    let account = banks_client
        .get_account(zk_token_account)
        .await
        .expect("get_account")
        .expect("zk_token_account not found");
    *spl_zk_token::state::ZkAccount::from_bytes(&account.data).unwrap()
}

#[cfg(feature = "test-bpf")]
async fn get_zk_token_balance(
    banks_client: &mut BanksClient,
    zk_token_account: Pubkey,
) -> (
    /* pending_balance: */ ElGamalCiphertext,
    /* available_balance: */ ElGamalCiphertext,
) {
    let zk_token_state = get_zk_token_state(banks_client, zk_token_account).await;

    (
        zk_token_state.pending_balance.try_into().unwrap(),
        zk_token_state.available_balance.try_into().unwrap(),
    )
}

// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the system program
#[cfg(feature = "test-bpf")]
#[tokio::test]
async fn test_configure_mint() {
    let owner = Keypair::new();
    let freeze_authority = Keypair::new();
    let auditor_pk = ElGamalKeypair::default().public;

    let mut program_test = program_test();
    let mint = add_token_mint_account(&mut program_test, Some(freeze_authority.pubkey()));
    let _token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 123);

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let omnibus_token_address = get_omnibus_token_address(&mint);
    let zk_mint_address = get_zk_mint_address(&mint);

    // Failure case: cannot configure the zk mint without the freeze authority signing
    let mut transaction = Transaction::new_with_payer(
        &[spl_zk_token::instruction::configure_mint(
            payer.pubkey(),
            mint,
            None,
            &[],
            None,
        )],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client
        .process_transaction(transaction)
        .await
        .unwrap_err();

    // Success case: configure the zk mint
    let mut transaction = Transaction::new_with_payer(
        &[spl_zk_token::instruction::configure_mint(
            payer.pubkey(),
            mint,
            Some(freeze_authority.pubkey()),
            &[],
            Some(Auditor {
                auditor_pk: auditor_pk.into(),
                enable_balance_credits_authority: Pubkey::default(),
            }),
        )],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &freeze_authority], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    // Omnibus account now exists
    assert_eq!(
        get_token_balance(&mut banks_client, omnibus_token_address).await,
        0
    );

    // ZkMint account now exists
    let zk_mint_account = banks_client
        .get_account(zk_mint_address)
        .await
        .expect("get_account")
        .expect("zk_mint_account not found");

    assert_eq!(zk_mint_account.owner, spl_zk_token::id());
    let zk_mint = pod_from_bytes::<state::ZkMint>(&zk_mint_account.data).unwrap();
    assert_eq!(zk_mint.mint, mint.into());
    assert!(zk_mint.auditor.auditor_enabled());
    assert_eq!(
        zk_mint.auditor.maybe_enable_balance_credits_authority(),
        None
    );
}

#[tokio::test]
#[ignore]
async fn test_update_auditor() {
    todo!()
}

// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the system program
#[cfg(feature = "test-bpf")]
#[tokio::test]
async fn test_configure_account() {
    let owner = Keypair::new();
    let elgamal_pk = ElGamalKeypair::default().public;

    let mut program_test = program_test();

    let mint = add_token_mint_account(&mut program_test, None);
    let token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 123);
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let zk_token_account = get_zk_token_address(&mint, &token_account);

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::configure_account(
            payer.pubkey(),
            zk_token_account,
            elgamal_pk,
            AeCiphertext::default(),
            token_account,
            owner.pubkey(),
            &[],
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    // Zk token account now exists
    let account = banks_client
        .get_account(zk_token_account)
        .await
        .expect("get_account")
        .expect("zk_token_account not found");
    assert_eq!(account.owner, id());
    let zk_token_state = spl_zk_token::state::ZkAccount::from_bytes(&account.data).unwrap();
    assert_eq!(zk_token_state.mint, mint.into());
    assert_eq!(zk_token_state.token_account, token_account.into());
    assert_eq!(zk_token_state.elgamal_pk, elgamal_pk.into());
    assert_eq!(zk_token_state.allow_balance_credits, false.into());
}

#[cfg(feature = "twoxtx")]
#[tokio::test]
async fn test_close_account() {
    let owner = Keypair::new();
    let reclaim_account = Keypair::new();

    let elgamal_keypair = ElGamalKeypair::default();
    let elgamal_pk = elgamal_keypair.public;

    let mut program_test = program_test();

    let mint = add_token_mint_account(&mut program_test, None);
    let token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 123);

    let zk_available_balance = 0u64;
    let zk_available_balance_ct = elgamal_pk.encrypt(zk_available_balance);
    let zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        token_account,
        elgamal_pk,
        zk_available_balance_ct,
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    let data =
        spl_zk_token::instruction::CloseAccountData::new(&elgamal_keypair, zk_available_balance_ct);

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::close_account(
            zk_token_account,
            token_account,
            reclaim_account.pubkey(),
            owner.pubkey(),
            &[],
            &data,
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    // zk_token_account is now gone
    assert_eq!(
        banks_client
            .get_account(zk_token_account)
            .await
            .expect("get_account"),
        None
    );

    //confirm reclaim_account balance is correct
    assert_eq!(
        banks_client
            .get_balance(reclaim_account.pubkey())
            .await
            .expect("get_balance"),
        ACCOUNT_RENT_EXEMPTION
    );
}

// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the SPL Token program
#[cfg(feature = "test-bpf")]
#[cfg(feature = "twoxtx")]
#[tokio::test]
async fn test_deposit() {
    let owner = Keypair::new();
    let elgamal_pk = ElGamalKeypair::default().public;

    let mut program_test = program_test();
    let mint = add_token_mint_account(&mut program_test, None);
    let omnibus_token_address = add_omnibus_token_account(&mut program_test, mint, 0);
    let token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 123);
    let zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        token_account,
        elgamal_pk,
        ElGamalCiphertext::default(), /* 0 balance */
    );
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    assert_eq!(
        get_token_balance(&mut banks_client, token_account).await,
        123
    );
    assert_eq!(
        get_token_balance(&mut banks_client, omnibus_token_address).await,
        0
    );

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::deposit(
            token_account,
            mint,
            zk_token_account,
            token_account,
            owner.pubkey(),
            &[],
            1,
            DECIMALS,
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    assert_eq!(
        get_token_balance(&mut banks_client, token_account).await,
        122
    );
    assert_eq!(
        get_token_balance(&mut banks_client, omnibus_token_address).await,
        1
    );

    let public = ElGamalPubkey::default();
    let expected_pending_ct = public.encrypt_with(1_u64, &PedersenOpening::default());

    assert_eq!(
        get_zk_token_balance(&mut banks_client, zk_token_account).await,
        (expected_pending_ct, ElGamalCiphertext::default())
    );

    assert_eq!(
        u64::from(
            get_zk_token_state(&mut banks_client, zk_token_account)
                .await
                .pending_balance_credit_counter
        ),
        1,
    );

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::apply_pending_balance(
            zk_token_account,
            token_account,
            owner.pubkey(),
            &[],
            /*expected_pending_balance_credit_counter=*/ 1,
            AeCiphertext::default(),
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    assert_eq!(
        get_zk_token_balance(&mut banks_client, zk_token_account).await,
        (ElGamalCiphertext::default(), expected_pending_ct)
    );
}

// Mark this test as BPF-only due to current `ProgramTest` limitations when CPIing into the SPL Token program
#[cfg(feature = "test-bpf")]
#[cfg(feature = "twoxtx")]
#[tokio::test]
async fn test_withdraw() {
    let owner = Keypair::new();
    let elgamal = ElGamalKeypair::default();

    let zk_available_balance = 123;
    let zk_available_balance_ct = elgamal.public.encrypt(zk_available_balance);

    let mut program_test = program_test();
    let mint = add_token_mint_account(&mut program_test, None);
    let omnibus_token_address =
        add_omnibus_token_account(&mut program_test, mint, zk_available_balance);
    let token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 0);

    let zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        token_account,
        elgamal.public,
        zk_available_balance_ct,
    );
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    assert_eq!(get_token_balance(&mut banks_client, token_account).await, 0);
    assert_eq!(
        get_token_balance(&mut banks_client, omnibus_token_address).await,
        123
    );

    let withdraw_data = spl_zk_token::instruction::WithdrawData::new(
        1,
        &elgamal,
        zk_available_balance,
        zk_available_balance_ct,
    );
    let zk_new_available_balance_ct = withdraw_data.final_balance_ct;

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::withdraw(
            zk_token_account,
            token_account,
            token_account,
            &mint,
            owner.pubkey(),
            &[],
            1,
            DECIMALS,
            AeCiphertext::default(),
            &withdraw_data,
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    assert_eq!(get_token_balance(&mut banks_client, token_account).await, 1);
    assert_eq!(
        get_token_balance(&mut banks_client, omnibus_token_address).await,
        122
    );

    assert_eq!(
        get_zk_token_balance(&mut banks_client, zk_token_account).await,
        (
            ElGamalCiphertext::default(),
            zk_new_available_balance_ct.try_into().unwrap()
        )
    );
}

#[cfg(feature = "twoxtx")]
#[tokio::test]
async fn test_transfer() {
    let owner = Keypair::new();
    let src_elgamal = ElGamalKeypair::default();
    let dst_elgamal = ElGamalKeypair::default();

    let src_zk_available_balance = 123_u64;
    let src_zk_available_balance_ct = src_elgamal.public.encrypt(src_zk_available_balance);

    let dst_zk_available_balance = 0_u64;
    let dst_zk_available_balance_ct = dst_elgamal.public.encrypt(dst_zk_available_balance);

    let mut program_test = program_test();
    let mint = add_token_mint_account(&mut program_test, None);

    let auditor_pk = ElGamalKeypair::default().public;
    let _zk_auditor_address = add_zk_mint_account(&mut program_test, mint, None);

    let src_token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 0);
    let src_zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        src_token_account,
        src_elgamal.public,
        src_zk_available_balance_ct,
    );
    let dst_token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 0);
    let dst_zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        dst_token_account,
        dst_elgamal.public,
        dst_zk_available_balance_ct,
    );
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let transfer_amount = 1;

    let transfer_data = spl_zk_token::instruction::TransferData::new(
        transfer_amount,
        src_zk_available_balance,
        src_zk_available_balance_ct,
        &src_elgamal,
        dst_elgamal.public,
        auditor_pk,
    );

    let mut instructions = spl_zk_token::instruction::transfer(
        src_zk_token_account,
        src_token_account,
        dst_zk_token_account,
        dst_token_account,
        &mint,
        owner.pubkey(),
        &[],
        AeCiphertext::default(),
        &transfer_data,
    );

    instructions.push(spl_memo::build_memo(
        b"A memo in the transfer transaction.....",
        &[],
    ));
    let mut transaction = Transaction::new_with_payer(&instructions, Some(&payer.pubkey()));
    transaction.sign(&[&payer, &owner], recent_blockhash);

    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    assert_eq!(
        u64::from(
            get_zk_token_state(&mut banks_client, dst_zk_token_account)
                .await
                .pending_balance_credit_counter
        ),
        1,
    );

    // TODO: Check balances of src_zk_token_account and dst_zk_token_accounts

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::apply_pending_balance(
            dst_zk_token_account,
            dst_token_account,
            owner.pubkey(),
            &[],
            1,
            AeCiphertext::default(),
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);
    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    // TODO: Check balance of dst_zk_token_account
}

#[cfg(feature = "twoxtx")]
#[tokio::test]
async fn test_transfer_self() {
    let owner = Keypair::new();

    let mut program_test = program_test();
    let mint = add_token_mint_account(&mut program_test, None);

    let auditor_pk = ElGamalKeypair::default().public;
    let _zk_auditor_address = add_zk_mint_account(&mut program_test, mint, None);

    let token_account = add_token_account(&mut program_test, mint, owner.pubkey(), 0);

    let elgamal = ElGamalKeypair::new(&owner, &token_account).unwrap();
    let zk_available_balance = 123_u64;
    let zk_available_balance_ct = elgamal.public.encrypt(zk_available_balance);

    let zk_token_account = add_zk_token_account(
        &mut program_test,
        mint,
        token_account,
        elgamal.public,
        zk_available_balance_ct,
    );
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let transfer_amount = 1;

    let transfer_data = spl_zk_token::instruction::TransferData::new(
        transfer_amount,
        zk_available_balance,
        zk_available_balance_ct,
        &elgamal,
        elgamal.public,
        auditor_pk,
    );

    let mut transaction = Transaction::new_with_payer(
        &spl_zk_token::instruction::transfer(
            zk_token_account,
            token_account,
            zk_token_account,
            token_account,
            &mint,
            owner.pubkey(),
            &[],
            AeCiphertext::default(),
            &transfer_data,
        ),
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &owner], recent_blockhash);

    assert_transaction_size(&transaction);
    banks_client.process_transaction(transaction).await.unwrap();

    assert_eq!(
        u64::from(
            get_zk_token_state(&mut banks_client, zk_token_account)
                .await
                .pending_balance_credit_counter
        ),
        1,
    );
}

#[tokio::test]
#[ignore]
async fn test_multisig() {
    todo!()
}
