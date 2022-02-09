//! Program state processor

use {
    crate::{instruction::*, pod::*, state::*, *},
    bytemuck::Pod,
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        instruction::Instruction,
        msg,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        program_option::COption,
        program_pack::Pack,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction,
        sysvar::{instructions::get_instruction_relative, Sysvar},
    },
    solana_zk_token_sdk::{
        zk_token_elgamal::{ops, pod},
        zk_token_proof_program,
    },
    std::result::Result,
};

fn decode_proof_instruction<T: Pod>(
    expected: ProofInstruction,
    instruction: &Instruction,
) -> Result<&T, ProgramError> {
    if instruction.program_id != zk_token_proof_program::id()
        || ProofInstruction::decode_type(&instruction.data) != Some(expected)
    {
        msg!("Unexpected proof instruction");
        return Err(ProgramError::InvalidInstructionData);
    }

    ProofInstruction::decode_data(&instruction.data).ok_or(ProgramError::InvalidInstructionData)
}

/// Validates that the provided `owner_account_info` is the expected owner, and is either a single
/// signer or an SPL Token Multisig account with sufficient signers
fn validate_spl_token_owner(
    expected_owner: &Pubkey,
    owner_account_info: &AccountInfo,
    signers: &[AccountInfo],
) -> ProgramResult {
    spl_token::processor::Processor::validate_owner(
        &spl_token::id(),
        expected_owner,
        owner_account_info,
        signers,
    )
}

fn validate_account_owner(account_info: &AccountInfo, owner: &Pubkey) -> ProgramResult {
    if account_info.owner == owner {
        Ok(())
    } else {
        Err(ProgramError::InvalidArgument)
    }
}

fn _validate_zk_token_account<'a, 'b>(
    zk_token_account_info: &'a AccountInfo<'b>,
    token_account_info: &AccountInfo,
    is_signer: Option<(
        /*owner_info:*/ &AccountInfo,
        /*signers:*/ &[AccountInfo],
    )>,
) -> Result<
    (
        PodAccountInfoData<'a, 'b, ZkAccount>,
        spl_token::state::Account,
    ),
    ProgramError,
> {
    validate_account_owner(token_account_info, &spl_token::id())?;
    let token_account = spl_token::state::Account::unpack(&token_account_info.data.borrow())?;
    if let Some((owner_info, signers)) = is_signer {
        validate_spl_token_owner(&token_account.owner, owner_info, signers)?;
    }

    let zk_token_account = ZkAccount::from_account_info(zk_token_account_info, &id())?;

    if zk_token_account.mint != token_account.mint {
        msg!("Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if zk_token_account.token_account != *token_account_info.key {
        msg!("Token account mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    Ok((zk_token_account, token_account))
}

fn validate_zk_token_account<'a, 'b>(
    zk_token_account_info: &'a AccountInfo<'b>,
    token_account_info: &AccountInfo,
) -> Result<
    (
        PodAccountInfoData<'a, 'b, ZkAccount>,
        spl_token::state::Account,
    ),
    ProgramError,
> {
    _validate_zk_token_account(zk_token_account_info, token_account_info, None)
}

fn validate_zk_token_account_is_signer<'a, 'b>(
    zk_token_account_info: &'a AccountInfo<'b>,
    token_account_info: &AccountInfo,
    owner_info: &AccountInfo,
    signers: &[AccountInfo],
) -> Result<
    (
        PodAccountInfoData<'a, 'b, ZkAccount>,
        spl_token::state::Account,
    ),
    ProgramError,
> {
    _validate_zk_token_account(
        zk_token_account_info,
        token_account_info,
        Some((owner_info, signers)),
    )
}

fn create_pda_account<'a>(
    funder: &AccountInfo<'a>,
    rent: &Rent,
    space: usize,
    owner: &Pubkey,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
    new_pda_signer_seeds: &[&[u8]],
) -> ProgramResult {
    if new_pda_account.lamports() > 0 {
        let required_lamports = rent
            .minimum_balance(space)
            .max(1)
            .saturating_sub(new_pda_account.lamports());

        if required_lamports > 0 {
            invoke(
                &system_instruction::transfer(funder.key, new_pda_account.key, required_lamports),
                &[
                    funder.clone(),
                    new_pda_account.clone(),
                    system_program.clone(),
                ],
            )?;
        }

        invoke_signed(
            &system_instruction::allocate(new_pda_account.key, space as u64),
            &[new_pda_account.clone(), system_program.clone()],
            &[new_pda_signer_seeds],
        )?;

        invoke_signed(
            &system_instruction::assign(new_pda_account.key, owner),
            &[new_pda_account.clone(), system_program.clone()],
            &[new_pda_signer_seeds],
        )
    } else {
        invoke_signed(
            &system_instruction::create_account(
                funder.key,
                new_pda_account.key,
                rent.minimum_balance(space).max(1),
                space as u64,
                owner,
            ),
            &[
                funder.clone(),
                new_pda_account.clone(),
                system_program.clone(),
            ],
            &[new_pda_signer_seeds],
        )
    }
}

/// Processes an [ConfigureMint] instruction.
fn process_configure_mint(accounts: &[AccountInfo], auditor: &state::Auditor) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let funder_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let zk_mint_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let rent_sysvar_info = next_account_info(account_info_iter)?;

    validate_account_owner(mint_info, &spl_token::id())?;

    let rent = &Rent::from_account_info(rent_sysvar_info)?;
    let mint = spl_token::state::Mint::unpack(&mint_info.data.borrow())?;

    if let COption::Some(freeze_authority) = mint.freeze_authority {
        // If the mint has a freeze authority, only the freeze authority may enabled confidential
        // transfers
        let authority_info = next_account_info(account_info_iter)?;
        validate_spl_token_owner(
            &freeze_authority,
            authority_info,
            account_info_iter.as_slice(),
        )?;
    } else {
        // If the mint has no freeze authority, anybody may enabled confidential transfers but
        // cannot configure an auditor
        if *auditor != state::Auditor::zeroed() {
            msg!("Error: auditor may not be configured on a mint with no freeze authority");
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Ensure omnibus token account address is correct
    let (omnibus_token_address, omnibus_token_bump_seed) =
        get_omnibus_token_address_with_seed(mint_info.key);

    if omnibus_token_address != *omnibus_info.key {
        msg!("Error: Omnibus token address does not match derivation");
        return Err(ProgramError::InvalidArgument);
    }

    let omnibus_token_account_signer_seeds: &[&[_]] = &[
        &mint_info.key.to_bytes(),
        br"omnibus",
        &[omnibus_token_bump_seed],
    ];

    // Ensure zk mint address is correct
    let (zk_mint_address, zk_mint_bump_seed) = get_zk_mint_address_with_seed(mint_info.key);
    if zk_mint_address != *zk_mint_info.key {
        msg!("Error: mint address does not match derivation");
        return Err(ProgramError::InvalidArgument);
    }

    let auditor_account_signer_seeds: &[&[_]] =
        &[&mint_info.key.to_bytes(), br"zk_mint", &[zk_mint_bump_seed]];

    msg!("Creating omnibus token account: {}", omnibus_info.key);
    create_pda_account(
        funder_info,
        rent,
        spl_token::state::Account::get_packed_len(),
        &spl_token::id(),
        system_program_info,
        omnibus_info,
        omnibus_token_account_signer_seeds,
    )?;
    invoke(
        &spl_token::instruction::initialize_account2(
            &spl_token::id(),
            omnibus_info.key,
            mint_info.key,
            omnibus_info.key,
        )?,
        &[
            omnibus_info.clone(),
            mint_info.clone(),
            spl_token_program_info.clone(),
            rent_sysvar_info.clone(),
        ],
    )?;

    msg!("Creating zk mint account: {}", zk_mint_info.key);
    create_pda_account(
        funder_info,
        rent,
        ZkMint::get_packed_len(),
        &id(),
        system_program_info,
        zk_mint_info,
        auditor_account_signer_seeds,
    )?;

    let mut zk_mint = ZkMint::from_account_info(zk_mint_info, &id())?.into_mut();
    zk_mint.mint = *mint_info.key;
    zk_mint.auditor = *auditor;
    Ok(())
}

/// Processes an [UpdateAuditor] instruction.
fn process_update_auditor(accounts: &[AccountInfo], new_auditor: &state::Auditor) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let zk_mint_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;

    validate_account_owner(mint_info, &spl_token::id())?;
    let mint = spl_token::state::Mint::unpack(&mint_info.data.borrow())?;

    if let COption::Some(freeze_authority) = mint.freeze_authority {
        // If the mint has a freeze authority, only the freeze authority may enabled confidential
        // transfers
        let authority_info = next_account_info(account_info_iter)?;
        validate_spl_token_owner(
            &freeze_authority,
            authority_info,
            account_info_iter.as_slice(),
        )?;
    } else {
        msg!("Error: auditor may not be updated on a mint with no freeze authority");
        return Err(ProgramError::InvalidArgument);
    }

    let mut zk_mint = ZkMint::from_account_info(zk_mint_info, &id())?.into_mut();

    if zk_mint.mint != *mint_info.key {
        msg!("Error: Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if zk_mint.auditor.auditor_enabled() {
        zk_mint.auditor = *new_auditor;
        Ok(())
    } else {
        // Once the auditor is disabled it cannot be re-enabled
        msg!("Error: auditor is disabled");
        Err(ProgramError::InvalidAccountData)
    }
}

/// Processes an [ConfigureAccount] instruction.
fn process_configure_account(
    accounts: &[AccountInfo],
    data: &ConfigureAccountInstructionData,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let funder_info = next_account_info(account_info_iter)?;
    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let rent_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    validate_account_owner(token_account_info, &spl_token::id())?;
    let token_account = spl_token::state::Account::unpack(&token_account_info.data.borrow())?;
    validate_spl_token_owner(
        &token_account.owner,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    // Ensure confidential account address derivation is correct
    let (zk_token_account_address, zk_token_account_bump_seed) =
        get_zk_token_address_with_seed(&token_account.mint, token_account_info.key);
    if zk_token_account_address != *zk_token_account_info.key {
        msg!("Error: zk token address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    let confidential_token_account_signer_seeds: &[&[_]] = &[
        &token_account.mint.to_bytes(),
        &token_account_info.key.to_bytes(),
        br"zk_account",
        &[zk_token_account_bump_seed],
    ];

    let rent = &Rent::from_account_info(rent_sysvar_info)?;

    msg!("Creating zk account: {}", zk_token_account_info.key);
    create_pda_account(
        funder_info,
        rent,
        ZkAccount::get_packed_len(),
        &id(),
        system_program_info,
        zk_token_account_info,
        confidential_token_account_signer_seeds,
    )?;

    let mut zk_token_account =
        ZkAccount::from_account_info(zk_token_account_info, &id())?.into_mut();
    zk_token_account.mint = token_account.mint;
    zk_token_account.token_account = *token_account_info.key;
    zk_token_account.elgamal_pk = data.elgamal_pk;

    /*
        An ElGamal ciphertext is of the form
          ElGamalCiphertext {
            msg_comm: r * H + x * G
            decrypt_handle: r * P
          }

        where
        - G, H: constants for the system (RistrettoPoint)
        - P: ElGamal public key component (RistrettoPoint)
        - r: encryption randomness (Scalar)
        - x: message (Scalar)

        Upon receiving a `ConfigureAccount` instruction, the ZK Token program should encrypt x=0 (i.e.
        Scalar::zero()) and store it as `pending_balance` and `available_balance`.

        For regular encryption, it is important that r is generated from a proper randomness source. But
        for the `ConfigureAccount` instruction, it is already known that x is always 0. So r can just be
        set Scalar::zero().

        This means that the ElGamalCiphertext should simply be
          ElGamalCiphertext {
            msg_comm: 0 * H + 0 * G = 0
            decrypt_handle: 0 * P = 0
          }

        This should just be encoded as [0; 64]
    */
    zk_token_account.pending_balance = pod::ElGamalCiphertext::zeroed();
    zk_token_account.available_balance = pod::ElGamalCiphertext::zeroed();
    zk_token_account.decryptable_available_balance = data.decryptable_zero_balance;

    Ok(())
}

/// Processes an [CloseAccount] instruction.
fn process_close_account(accounts: &[AccountInfo], proof_instruction_offset: i64) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let reclaim_info = next_account_info(account_info_iter)?;
    let instructions_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (zk_token_account, _token_account) = validate_zk_token_account_is_signer(
        zk_token_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    let previous_instruction =
        get_instruction_relative(proof_instruction_offset, instructions_sysvar_info)?;
    let data = decode_proof_instruction::<CloseAccountData>(
        ProofInstruction::VerifyCloseAccount,
        &previous_instruction,
    )?;

    if zk_token_account.pending_balance != pod::ElGamalCiphertext::zeroed() {
        msg!("Pending balance is not zero");
        return Err(ProgramError::InvalidAccountData);
    }

    if zk_token_account.available_balance != data.ciphertext {
        msg!("Available balance mismatch");
        return Err(ProgramError::InvalidInstructionData);
    }

    // Zero account data
    *zk_token_account.into_mut() = ZkAccount::zeroed();

    // Drain lamports
    let dest_starting_lamports = reclaim_info.lamports();
    **reclaim_info.lamports.borrow_mut() = dest_starting_lamports
        .checked_add(zk_token_account_info.lamports())
        .ok_or(ProgramError::InvalidAccountData)?;
    **zk_token_account_info.lamports.borrow_mut() = 0;

    Ok(())
}

/// Processes a [Deposit] instruction.
fn process_deposit(accounts: &[AccountInfo], amount: u64, decimals: u8) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let source_token_account_info = next_account_info(account_info_iter)?;
    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;
    let signers = account_info_iter.as_slice();

    let (zk_token_account, token_account) =
        validate_zk_token_account(zk_token_account_info, token_account_info)?;

    if token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    if !bool::from(&zk_token_account.allow_balance_credits) {
        msg!("Error: deposit instruction disabled");
        return Err(ProgramError::InvalidArgument);
    }

    // Ensure omnibus token account address derivation is correct
    if get_omnibus_token_address(mint_info.key) != *omnibus_info.key {
        msg!("Error: Omnibus token address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    // Deposit the tokens into the omnibus account
    let signer_pubkeys = signers.iter().map(|ai| ai.key).collect::<Vec<_>>();
    let mut accounts = vec![
        source_token_account_info.clone(),
        mint_info.clone(),
        omnibus_info.clone(),
        owner_info.clone(),
        spl_token_program_info.clone(),
    ];
    for signer in signers {
        accounts.push(signer.clone());
    }
    invoke(
        &spl_token::instruction::transfer_checked(
            &spl_token::id(),
            source_token_account_info.key,
            mint_info.key,
            omnibus_info.key,
            owner_info.key,
            signer_pubkeys.as_slice(),
            amount,
            decimals,
        )?,
        &accounts,
    )?;

    let mut zk_token_account = zk_token_account.into_mut();
    zk_token_account.pending_balance = ops::add_to(&zk_token_account.pending_balance, amount)
        .ok_or(ProgramError::InvalidInstructionData)?;

    zk_token_account.pending_balance_credit_counter =
        (u64::from(zk_token_account.pending_balance_credit_counter) + 1).into();

    Ok(())
}

/// Processes a [Withdraw] instruction.
fn process_withdraw(
    accounts: &[AccountInfo],
    amount: u64,
    decimals: u8,
    new_decryptable_available_balance: pod::AeCiphertext,
    proof_instruction_offset: i64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let dest_token_account_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let instructions_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (zk_token_account, token_account) = validate_zk_token_account_is_signer(
        zk_token_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    if token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    let previous_instruction =
        get_instruction_relative(proof_instruction_offset, instructions_sysvar_info)?;

    let data = decode_proof_instruction::<WithdrawData>(
        ProofInstruction::VerifyWithdraw,
        &previous_instruction,
    )?;

    let mut zk_token_account = zk_token_account.into_mut();
    zk_token_account.available_balance =
        ops::subtract_from(&zk_token_account.available_balance, amount)
            .ok_or(ProgramError::InvalidInstructionData)?;

    if zk_token_account.available_balance != data.final_ciphertext {
        msg!("Available balance mismatch");
        return Err(ProgramError::InvalidInstructionData);
    }

    zk_token_account.decryptable_available_balance = new_decryptable_available_balance;

    // Ensure omnibus token account address derivation is correct
    let (omnibus_token_address, omnibus_token_bump_seed) =
        get_omnibus_token_address_with_seed(mint_info.key);
    if omnibus_token_address != *omnibus_info.key {
        msg!("Error: Omnibus token address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    let omnibus_token_account_signer_seeds: &[&[_]] = &[
        &mint_info.key.to_bytes(),
        br"omnibus",
        &[omnibus_token_bump_seed],
    ];

    // Withdraw tokens from the omnibus account
    invoke_signed(
        &spl_token::instruction::transfer_checked(
            &spl_token::id(),
            omnibus_info.key,
            mint_info.key,
            dest_token_account_info.key,
            omnibus_info.key,
            &[],
            amount,
            decimals,
        )?,
        &[
            omnibus_info.clone(),
            mint_info.clone(),
            dest_token_account_info.clone(),
            omnibus_info.clone(),
            spl_token_program_info.clone(),
        ],
        &[omnibus_token_account_signer_seeds],
    )?;

    Ok(())
}
/// Processes a [Transfer] instruction.
fn process_transfer(
    accounts: &[AccountInfo],
    new_source_decryptable_available_balance: pod::AeCiphertext,
    proof_instruction_offset: i64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let receiver_zk_token_account_info = next_account_info(account_info_iter)?;
    let receiver_token_account_info = next_account_info(account_info_iter)?;
    let zk_mint_info = next_account_info(account_info_iter)?;
    let instructions_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (zk_token_account, token_account) = validate_zk_token_account_is_signer(
        zk_token_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    let (receiver_zk_token_account, receiver_token_account) =
        validate_zk_token_account(receiver_zk_token_account_info, receiver_token_account_info)?;

    let zk_mint = ZkMint::from_account_info(zk_mint_info, &id())?;

    if zk_token_account.mint != receiver_zk_token_account.mint
        || zk_token_account.mint != zk_mint.mint
    {
        msg!("Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if token_account.is_frozen() || receiver_token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    if !bool::from(&receiver_zk_token_account.allow_balance_credits) {
        msg!("Error: transfer instruction disabled");
        return Err(ProgramError::InvalidArgument);
    }

    let previous_instruction =
        get_instruction_relative(proof_instruction_offset, instructions_sysvar_info)?;
    let data = decode_proof_instruction::<TransferData>(
        ProofInstruction::VerifyTransfer,
        &previous_instruction,
    )?;

    if data.transfer_pubkeys.source != zk_token_account.elgamal_pk
        || data.transfer_pubkeys.dest != receiver_zk_token_account.elgamal_pk
        || (zk_mint.auditor.auditor_enabled()
            && data.transfer_pubkeys.auditor != zk_mint.auditor.auditor_pk)
    {
        msg!("Error: ElGamal public key mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let new_source_available_balance = {
        // Combine commitments and handles
        let source_lo_ct = pod::ElGamalCiphertext::from((
            data.ciphertext_lo.commitment,
            data.ciphertext_lo.source,
        ));
        let source_hi_ct = pod::ElGamalCiphertext::from((
            data.ciphertext_hi.commitment,
            data.ciphertext_hi.source,
        ));

        ops::subtract_with_lo_hi(
            &zk_token_account.available_balance,
            &source_lo_ct,
            &source_hi_ct,
        )
        .ok_or(ProgramError::InvalidInstructionData)?
    };

    let new_receiver_pending_balance = {
        let dest_lo_ct =
            pod::ElGamalCiphertext::from((data.ciphertext_lo.commitment, data.ciphertext_lo.dest));

        let dest_hi_ct =
            pod::ElGamalCiphertext::from((data.ciphertext_hi.commitment, data.ciphertext_hi.dest));

        ops::add_with_lo_hi(
            &receiver_zk_token_account.pending_balance,
            &dest_lo_ct,
            &dest_hi_ct,
        )
        .ok_or(ProgramError::InvalidInstructionData)?
    };

    let new_receiver_pending_balance_credit_counter =
        (u64::from(receiver_zk_token_account.pending_balance_credit_counter) + 1).into();

    let receiver_zk_token_account =
        if zk_token_account_info.key == receiver_zk_token_account_info.key {
            drop(receiver_zk_token_account);
            None
        } else {
            Some(receiver_zk_token_account.into_mut())
        };

    let mut zk_token_account = zk_token_account.into_mut();

    zk_token_account.available_balance = new_source_available_balance;
    zk_token_account.decryptable_available_balance = new_source_decryptable_available_balance;

    let mut receiver_zk_token_account = receiver_zk_token_account.unwrap_or(zk_token_account);

    receiver_zk_token_account.pending_balance = new_receiver_pending_balance;
    receiver_zk_token_account.pending_balance_credit_counter =
        new_receiver_pending_balance_credit_counter;

    Ok(())
}

/// Processes an [ApplyPendingBalance] instruction.
fn process_apply_pending_balance(
    accounts: &[AccountInfo],
    expected_pending_balance_credit_counter: PodU64,
    new_decryptable_available_balance: pod::AeCiphertext,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (zk_token_account, _token_account) = validate_zk_token_account_is_signer(
        zk_token_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    let mut zk_token_account = zk_token_account.into_mut();

    zk_token_account.available_balance = ops::add(
        &zk_token_account.available_balance,
        &zk_token_account.pending_balance,
    )
    .ok_or(ProgramError::InvalidInstructionData)?;

    zk_token_account.actual_pending_balance_credit_counter =
        zk_token_account.pending_balance_credit_counter;
    zk_token_account.expected_pending_balance_credit_counter =
        expected_pending_balance_credit_counter;
    zk_token_account.decryptable_available_balance = new_decryptable_available_balance;
    zk_token_account.pending_balance = pod::ElGamalCiphertext::zeroed();

    Ok(())
}

/// Processes an [EnableBalanceCredits] instruction.
fn process_enable_balance_credits(accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let zk_mint_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (zk_token_account, token_account) =
        validate_zk_token_account(zk_token_account_info, token_account_info)?;

    // Ensure zk mint address is correct
    let zk_mint_address = get_zk_mint_address(&zk_token_account.mint);
    if zk_mint_address != *zk_mint_info.key {
        msg!("Error: zk mint address does not match derivation");
        return Err(ProgramError::InvalidArgument);
    }

    let zk_mint = ZkMint::from_account_info(zk_mint_info, &id())?;
    let authority = zk_mint
        .auditor
        .maybe_enable_balance_credits_authority()
        .unwrap_or(&token_account.owner);

    validate_spl_token_owner(authority, owner_info, account_info_iter.as_slice())?;

    zk_token_account.into_mut().allow_balance_credits = true.into();
    Ok(())
}

/// Processes an [DisableBalanceCredits] instruction.
fn process_disable_balance_credits(accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let zk_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (zk_token_account, _token_account) = validate_zk_token_account_is_signer(
        zk_token_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    zk_token_account.into_mut().allow_balance_credits = false.into();

    Ok(())
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    match decode_instruction_type(input)? {
        ZkTokenInstruction::ConfigureMint => {
            msg!("ConfigureMint!");
            process_configure_mint(accounts, decode_instruction_data::<state::Auditor>(input)?)
        }
        ZkTokenInstruction::UpdateAuditor => {
            msg!("UpdateAuditor");
            process_update_auditor(accounts, decode_instruction_data::<state::Auditor>(input)?)
        }
        ZkTokenInstruction::ConfigureAccount => {
            msg!("ConfigureAccount");
            process_configure_account(
                accounts,
                decode_instruction_data::<ConfigureAccountInstructionData>(input)?,
            )
        }
        ZkTokenInstruction::CloseAccount => {
            msg!("CloseAccount");
            let data = decode_instruction_data::<CloseInstructionData>(input)?;
            process_close_account(accounts, data.proof_instruction_offset as i64)
        }
        ZkTokenInstruction::Deposit => {
            msg!("Deposit");
            let data = decode_instruction_data::<DepositInstructionData>(input)?;
            process_deposit(accounts, data.amount.into(), data.decimals)
        }
        ZkTokenInstruction::Withdraw => {
            msg!("Withdraw");
            let data = decode_instruction_data::<WithdrawInstructionData>(input)?;
            process_withdraw(
                accounts,
                data.amount.into(),
                data.decimals,
                data.new_decryptable_available_balance,
                data.proof_instruction_offset as i64,
            )
        }
        ZkTokenInstruction::Transfer => {
            msg!("Transfer");
            let data = decode_instruction_data::<TransferInstructionData>(input)?;
            process_transfer(
                accounts,
                data.new_source_decryptable_available_balance,
                data.proof_instruction_offset as i64,
            )
        }
        ZkTokenInstruction::ApplyPendingBalance => {
            msg!("ApplyPendingBalance");

            let data = decode_instruction_data::<ApplyPendingBalanceData>(input)?;

            process_apply_pending_balance(
                accounts,
                data.expected_pending_balance_credit_counter,
                data.new_decryptable_available_balance,
            )
        }
        ZkTokenInstruction::DisableBalanceCredits => {
            msg!("DisableBalanceCredits");
            process_disable_balance_credits(accounts)
        }
        ZkTokenInstruction::EnableBalanceCredits => {
            msg!("EnableBalanceCredits");
            process_enable_balance_credits(accounts)
        }
    }
}
