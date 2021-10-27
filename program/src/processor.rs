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
        sysvar::{self, Sysvar},
    },
    spl_zk_token_sdk::{
        zk_token_elgamal::{ops, pod},
        zk_token_proof_program,
    },
    std::result::Result,
};

/// Returns the previous `Instruction` in the currently executing `Transaction`
fn get_previous_instruction(
    instruction_sysvar_account_info: &AccountInfo,
) -> Result<Instruction, ProgramError> {
    if *instruction_sysvar_account_info.key != sysvar::instructions::id() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let instruction_sysvar = instruction_sysvar_account_info.data.borrow();

    let current_instruction = sysvar::instructions::load_current_index(&instruction_sysvar);
    if current_instruction == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    sysvar::instructions::load_instruction_at(current_instruction as usize - 1, &instruction_sysvar)
        .map_err(|_| ProgramError::InvalidInstructionData)
}

/// Returns the previous `Instruction` in the currently executing `Transaction`
fn decode_proof_instruction<T: Pod>(
    expected: ProofInstruction,
    instruction: &Instruction,
) -> Result<&T, ProgramError> {
    if ProofInstruction::decode_type(&zk_token_proof_program::id(), &instruction.data)
        != Some(expected)
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

fn _validate_confidential_account<'a, 'b>(
    confidential_account_info: &'a AccountInfo<'b>,
    token_account_info: &AccountInfo,
    is_signer: Option<(
        /*owner_info:*/ &AccountInfo,
        /*signers:*/ &[AccountInfo],
    )>,
) -> Result<
    (
        PodAccountInfoData<'a, 'b, ConfidentialAccount>,
        spl_token::state::Account,
    ),
    ProgramError,
> {
    validate_account_owner(token_account_info, &spl_token::id())?;
    let token_account = spl_token::state::Account::unpack(&token_account_info.data.borrow())?;
    if let Some((owner_info, signers)) = is_signer {
        validate_spl_token_owner(&token_account.owner, owner_info, signers)?;
    }

    let confidential_account =
        ConfidentialAccount::from_account_info(confidential_account_info, &id())?;

    if confidential_account.mint != token_account.mint {
        msg!("Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if confidential_account.token_account != *token_account_info.key {
        msg!("Token account mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    Ok((confidential_account, token_account))
}

fn validate_confidential_account<'a, 'b>(
    confidential_account_info: &'a AccountInfo<'b>,
    token_account_info: &AccountInfo,
) -> Result<
    (
        PodAccountInfoData<'a, 'b, ConfidentialAccount>,
        spl_token::state::Account,
    ),
    ProgramError,
> {
    _validate_confidential_account(confidential_account_info, token_account_info, None)
}

fn validate_confidential_account_is_signer<'a, 'b>(
    confidential_account_info: &'a AccountInfo<'b>,
    token_account_info: &AccountInfo,
    owner_info: &AccountInfo,
    signers: &[AccountInfo],
) -> Result<
    (
        PodAccountInfoData<'a, 'b, ConfidentialAccount>,
        spl_token::state::Account,
    ),
    ProgramError,
> {
    _validate_confidential_account(
        confidential_account_info,
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
fn process_configure_mint(
    accounts: &[AccountInfo],
    auditor_pk: Option<&pod::ElGamalPubkey>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let funder_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let auditor_info = next_account_info(account_info_iter)?;
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
        if auditor_pk.is_some() {
            msg!("Error: auditor may not be configured on a mint with no freeze authority");
            return Err(ProgramError::InvalidArgument);
        }
    }

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

    // Ensure auditor account address derivation is correct
    let (auditor_address, auditor_bump_seed) = get_auditor_address_with_seed(mint_info.key);
    if auditor_address != *auditor_info.key {
        msg!("Error: auditor address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    let auditor_account_signer_seeds: &[&[_]] =
        &[&mint_info.key.to_bytes(), br"auditor", &[auditor_bump_seed]];

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

    msg!("Creating auditor account: {}", auditor_info.key);
    create_pda_account(
        funder_info,
        rent,
        Auditor::get_packed_len(),
        &id(),
        system_program_info,
        auditor_info,
        auditor_account_signer_seeds,
    )?;

    let mut auditor = Auditor::from_account_info(auditor_info, &id())?;

    auditor.mint = *mint_info.key;
    if let Some(auditor_pk) = auditor_pk {
        auditor.enabled = true.into();
        auditor.elgamal_pk = *auditor_pk;
    }

    Ok(())
}

/// Processes an [UpdateAuditor] instruction.
fn process_update_auditor(
    accounts: &[AccountInfo],
    new_auditor_pk: Option<&pod::ElGamalPubkey>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let auditor_info = next_account_info(account_info_iter)?;
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

    let mut auditor = Auditor::from_account_info(auditor_info, &id())?;

    if auditor.mint != *mint_info.key {
        msg!("Error: Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if !bool::from(&auditor.enabled) {
        msg!("Error: auditor is disabled");
        return Err(ProgramError::InvalidAccountData);
    }

    match new_auditor_pk {
        Some(new_auditor_pk) => auditor.elgamal_pk = *new_auditor_pk,
        None => {
            auditor.enabled = false.into();
        }
    }

    Ok(())
}

/// Processes an [ConfigureAccount] instruction.
fn process_configure_account(
    accounts: &[AccountInfo],
    data: &ConfigureAccountInstructionData,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let funder_info = next_account_info(account_info_iter)?;
    let confidential_account_info = next_account_info(account_info_iter)?;
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
    let (confidential_address, bump_seed) =
        get_confidential_token_address_with_seed(&token_account.mint, token_account_info.key);
    if confidential_address != *confidential_account_info.key {
        msg!("Error: Confidential address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    let confidential_token_account_signer_seeds: &[&[_]] = &[
        &token_account.mint.to_bytes(),
        &token_account_info.key.to_bytes(),
        br"confidential",
        &[bump_seed],
    ];

    let rent = &Rent::from_account_info(rent_sysvar_info)?;

    msg!(
        "Creating confidential account: {}",
        confidential_account_info.key
    );
    create_pda_account(
        funder_info,
        rent,
        ConfidentialAccount::get_packed_len(),
        &id(),
        system_program_info,
        confidential_account_info,
        confidential_token_account_signer_seeds,
    )?;

    let mut confidential_account =
        ConfidentialAccount::from_account_info(confidential_account_info, &id())?;
    confidential_account.mint = token_account.mint;
    confidential_account.token_account = *token_account_info.key;
    confidential_account.elgamal_pk = data.elgamal_pk;
    confidential_account.allow_pending_balance_credits = true.into();

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
    confidential_account.pending_balance = pod::ElGamalCiphertext::zeroed();
    confidential_account.available_balance = pod::ElGamalCiphertext::zeroed();
    confidential_account.decryptable_balance = data.decryptable_zero_balance;

    Ok(())
}

/// Processes an [CloseAccount] instruction.
fn process_close_account(accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let reclaim_info = next_account_info(account_info_iter)?;
    let instructions_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (mut confidential_account, _token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    let previous_instruction = get_previous_instruction(instructions_sysvar_info)?;
    let data = decode_proof_instruction::<CloseAccountData>(
        ProofInstruction::VerifyCloseAccount,
        &previous_instruction,
    )?;

    if confidential_account.pending_balance != pod::ElGamalCiphertext::zeroed() {
        msg!("Pending balance is not zero");
        return Err(ProgramError::InvalidAccountData);
    }

    if confidential_account.available_balance != data.balance {
        msg!("Available balance mismatch");
        return Err(ProgramError::InvalidInstructionData);
    }

    // Zero account data
    *confidential_account = ConfidentialAccount::zeroed();

    // Drain lamports
    let dest_starting_lamports = reclaim_info.lamports();
    **reclaim_info.lamports.borrow_mut() = dest_starting_lamports
        .checked_add(confidential_account_info.lamports())
        .ok_or(ProgramError::InvalidAccountData)?;
    **confidential_account_info.lamports.borrow_mut() = 0;

    Ok(())
}

/// Processes a [Deposit] instruction.
fn process_deposit(accounts: &[AccountInfo], amount: u64, decimals: u8) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let source_token_account_info = next_account_info(account_info_iter)?;
    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;
    let signers = account_info_iter.as_slice();

    let (mut confidential_account, token_account) =
        validate_confidential_account(confidential_account_info, token_account_info)?;

    if token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    if !bool::from(&confidential_account.allow_pending_balance_credits) {
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

    confidential_account.pending_balance =
        ops::add_to(&confidential_account.pending_balance, amount)
            .ok_or(ProgramError::InvalidInstructionData)?;

    confidential_account.pending_balance_credit_counter =
        (u64::from(confidential_account.pending_balance_credit_counter) + 1).into();

    Ok(())
}

/// Processes a [Withdraw] instruction.
fn process_withdraw(
    accounts: &[AccountInfo],
    amount: u64,
    decimals: u8,
    new_decryptable_balance: pod::AesCiphertext,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let dest_token_account_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let instructions_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (mut confidential_account, token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    if token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    let previous_instruction = get_previous_instruction(instructions_sysvar_info)?;
    let data = decode_proof_instruction::<WithdrawData>(
        ProofInstruction::VerifyWithdraw,
        &previous_instruction,
    )?;

    confidential_account.available_balance =
        ops::subtract_from(&confidential_account.available_balance, amount)
            .ok_or(ProgramError::InvalidInstructionData)?;

    if confidential_account.available_balance != data.final_balance_ct {
        msg!("Available balance mismatch");
        return Err(ProgramError::InvalidInstructionData);
    }

    confidential_account.decryptable_balance = new_decryptable_balance;

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
    new_source_decryptable_balance: pod::AesCiphertext,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let receiver_confidential_account_info = next_account_info(account_info_iter)?;
    let receiver_token_account_info = next_account_info(account_info_iter)?;
    let auditor_info = next_account_info(account_info_iter)?;
    let instructions_sysvar_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (mut confidential_account, token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    let (mut receiver_confidential_account, receiver_token_account) =
        validate_confidential_account(
            receiver_confidential_account_info,
            receiver_token_account_info,
        )?;

    let auditor = Auditor::from_account_info(auditor_info, &id())?;

    if confidential_account.mint != receiver_confidential_account.mint
        || confidential_account.mint != auditor.mint
    {
        msg!("Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if token_account.is_frozen() || receiver_token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    if !bool::from(&receiver_confidential_account.allow_pending_balance_credits) {
        msg!("Error: transfer instruction disabled");
        return Err(ProgramError::InvalidArgument);
    }

    let previous_instruction = get_previous_instruction(instructions_sysvar_info)?;
    let data = decode_proof_instruction::<TransferData>(
        ProofInstruction::VerifyTransfer,
        &previous_instruction,
    )?;

    if data.transfer_public_keys.source_pk != confidential_account.elgamal_pk
        || data.transfer_public_keys.dest_pk != receiver_confidential_account.elgamal_pk
        || (bool::from(&auditor.enabled)
            && data.transfer_public_keys.auditor_pk != auditor.elgamal_pk)
    {
        msg!("Error: ElGamal public key mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    // Subtract from source available balance
    {
        // Combine commitments and handles
        let source_lo_ct =
            pod::ElGamalCiphertext::from((data.amount_comms.lo, data.decrypt_handles_lo.source));
        let source_hi_ct =
            pod::ElGamalCiphertext::from((data.amount_comms.hi, data.decrypt_handles_hi.source));

        confidential_account.available_balance = ops::subtract_with_lo_hi(
            &confidential_account.available_balance,
            &source_lo_ct,
            &source_hi_ct,
        )
        .ok_or(ProgramError::InvalidInstructionData)?;
    }

    // Update source decryptable balance
    confidential_account.decryptable_balance = new_source_decryptable_balance;

    // Add to destination pending balance
    {
        let dest_lo_ct =
            pod::ElGamalCiphertext::from((data.amount_comms.lo, data.decrypt_handles_lo.dest));

        let dest_hi_ct =
            pod::ElGamalCiphertext::from((data.amount_comms.hi, data.decrypt_handles_hi.dest));

        receiver_confidential_account.pending_balance = ops::add_with_lo_hi(
            &receiver_confidential_account.pending_balance,
            &dest_lo_ct,
            &dest_hi_ct,
        )
        .ok_or(ProgramError::InvalidInstructionData)?;
    }

    receiver_confidential_account.pending_balance_credit_counter =
        (u64::from(receiver_confidential_account.pending_balance_credit_counter) + 1).into();

    Ok(())
}

/// Processes an [ApplyPendingBalance] instruction.
fn process_apply_pending_balance(
    accounts: &[AccountInfo],
    expected_pending_balance_credit_counter: PodU64,
    new_decryptable_balance: pod::AesCiphertext,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (mut confidential_account, _token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    confidential_account.available_balance = ops::add(
        &confidential_account.available_balance,
        &confidential_account.pending_balance,
    )
    .ok_or(ProgramError::InvalidInstructionData)?;

    confidential_account.actual_pending_balance_credit_counter =
        confidential_account.pending_balance_credit_counter;
    confidential_account.expected_pending_balance_credit_counter =
        expected_pending_balance_credit_counter;
    confidential_account.decryptable_balance = new_decryptable_balance;
    confidential_account.pending_balance = pod::ElGamalCiphertext::zeroed();

    Ok(())
}

/// Processes an [AllowPendingBalanceCredits] or [RejectPendingBalanceCredits] instruction.
fn process_allow_reject_pending_balance_credits(
    accounts: &[AccountInfo],
    allow_pending_balance_credits: bool,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (mut confidential_account, _token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    confidential_account.allow_pending_balance_credits = allow_pending_balance_credits.into();

    Ok(())
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    match decode_instruction_type(input)? {
        ConfidentialTokenInstruction::ConfigureMint => {
            msg!("ConfigureMint!");
            let auditor_pk =
                decode_optional_instruction_data::<ConfigureMintInstructionData>(input)?
                    .map(|d| &d.auditor_pk);
            process_configure_mint(accounts, auditor_pk)
        }
        ConfidentialTokenInstruction::UpdateAuditor => {
            msg!("UpdateAuditor");
            let new_auditor_pk =
                decode_optional_instruction_data::<UpdateAuditorInstructionData>(input)?
                    .map(|d| &d.new_auditor_pk);
            process_update_auditor(accounts, new_auditor_pk)
        }
        ConfidentialTokenInstruction::ConfigureAccount => {
            msg!("ConfigureAccount");
            process_configure_account(
                accounts,
                decode_instruction_data::<ConfigureAccountInstructionData>(input)?,
            )
        }
        ConfidentialTokenInstruction::CloseAccount => {
            msg!("CloseAccount");
            process_close_account(accounts)
        }
        ConfidentialTokenInstruction::Deposit => {
            msg!("Deposit");
            let data = decode_instruction_data::<DepositInstructionData>(input)?;
            process_deposit(accounts, data.amount.into(), data.decimals)
        }
        ConfidentialTokenInstruction::Withdraw => {
            msg!("Withdraw");
            let data = decode_instruction_data::<WithdrawInstructionData>(input)?;
            process_withdraw(
                accounts,
                data.amount.into(),
                data.decimals,
                data.new_decryptable_balance,
            )
        }
        ConfidentialTokenInstruction::Transfer => {
            msg!("Transfer");
            let data = decode_instruction_data::<TransferInstructionData>(input)?;
            process_transfer(accounts, data.new_source_decryptable_balance)
        }
        ConfidentialTokenInstruction::ApplyPendingBalance => {
            msg!("ApplyPendingBalance");

            let data = decode_instruction_data::<ApplyPendingBalanceData>(input)?;

            process_apply_pending_balance(
                accounts,
                data.expected_pending_balance_credit_counter,
                data.new_decryptable_balance,
            )
        }
        ConfidentialTokenInstruction::RejectPendingBalanceCredits => {
            msg!("RejectPendingBalanceCredits");
            process_allow_reject_pending_balance_credits(accounts, false)
        }
        ConfidentialTokenInstruction::AllowPendingBalanceCredits => {
            msg!("AllowPendingBalanceCredits");
            process_allow_reject_pending_balance_credits(accounts, true)
        }
    }
}
