//! Program state processor

use {
    crate::{instruction::*, state::*, *},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        msg,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        program_option::COption,
        program_pack::Pack,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction,
        sysvar::Sysvar,
    },
    std::result::Result,
};

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

fn validate_confidential_account(
    confidential_account_info: &AccountInfo,
    token_account_info: &AccountInfo,
) -> Result<(ConfidentialAccount, spl_token::state::Account), ProgramError> {
    validate_account_owner(token_account_info, &spl_token::id())?;
    validate_account_owner(confidential_account_info, &id())?;

    let token_account = spl_token::state::Account::unpack(&token_account_info.data.borrow())?;
    let confidential_account =
        ConfidentialAccount::unpack_from_slice(&confidential_account_info.data.borrow())?;

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

fn validate_confidential_account_is_signer(
    confidential_account_info: &AccountInfo,
    token_account_info: &AccountInfo,
    owner_info: &AccountInfo,
    signers: &[AccountInfo],
) -> Result<(ConfidentialAccount, spl_token::state::Account), ProgramError> {
    validate_account_owner(token_account_info, &spl_token::id())?;
    validate_account_owner(confidential_account_info, &id())?;

    let token_account = spl_token::state::Account::unpack(&token_account_info.data.borrow())?;
    validate_spl_token_owner(&token_account.owner, owner_info, signers)?;

    let confidential_account =
        ConfidentialAccount::unpack_from_slice(&confidential_account_info.data.borrow())?;

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

fn create_pda_account<'a>(
    funder: &AccountInfo<'a>,
    rent: &Rent,
    space: usize,
    owner: &Pubkey,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
    new_pda_signer_seeds: &[&[u8]],
) -> ProgramResult {
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
}

/// Processes an [ConfigureMint] instruction.
fn process_configure_mint(
    accounts: &[AccountInfo],
    transfer_auditor_pk: Option<ElGamalPK>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let funder_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let transfer_auditor_info = next_account_info(account_info_iter)?;
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
        // cannot configure a transfer auditor
        if transfer_auditor_pk.is_some() {
            msg!(
                "Error: Transfer auditor may not be configured on a mint with no freeze authority"
            );
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Ensure omnibus token account address derivation is correct
    let (omnibus_token_address, omnibus_token_bump_seed) =
        get_omnibus_token_address_with_seed(&mint_info.key);

    if omnibus_token_address != *omnibus_info.key {
        msg!("Error: Omnibus token address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    let omnibus_token_account_signer_seeds: &[&[_]] = &[
        &mint_info.key.to_bytes(),
        br"omnibus",
        &[omnibus_token_bump_seed],
    ];

    // Ensure transfer auditor account address derivation is correct
    let (transfer_auditor_address, transfer_auditor_bump_seed) =
        get_transfer_auditor_address_with_seed(&mint_info.key);
    if transfer_auditor_address != *transfer_auditor_info.key {
        msg!("Error: Transfer auditor address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    let transfer_auditor_account_signer_seeds: &[&[_]] = &[
        &mint_info.key.to_bytes(),
        br"transfer auditor",
        &[transfer_auditor_bump_seed],
    ];

    msg!("Creating omnibus token account: {}", omnibus_info.key);
    create_pda_account(
        funder_info,
        &rent,
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

    msg!(
        "Creating transfer auditor account: {}",
        transfer_auditor_info.key
    );
    create_pda_account(
        funder_info,
        &rent,
        TransferAuditor::get_packed_len(),
        &id(),
        system_program_info,
        transfer_auditor_info,
        transfer_auditor_account_signer_seeds,
    )?;

    TransferAuditor {
        mint: *mint_info.key,
        transfer_auditor_pk,
    }
    .pack_into_slice(&mut transfer_auditor_info.data.borrow_mut());

    Ok(())
}

/// Processes an [UpdateTransferAuditor] instruction.
fn process_update_transfer_auditor(
    accounts: &[AccountInfo],
    new_transfer_auditor_pk: Option<ElGamalPK>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let transfer_auditor_info = next_account_info(account_info_iter)?;
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
        msg!("Error: Transfer auditor may not be updated on a mint with no freeze authority");
        return Err(ProgramError::InvalidArgument);
    }

    let mut transfer_auditor =
        state::TransferAuditor::unpack_from_slice(&transfer_auditor_info.data.borrow())?;

    if transfer_auditor.mint != *mint_info.key {
        msg!("Error: Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    transfer_auditor.transfer_auditor_pk = new_transfer_auditor_pk;
    transfer_auditor.pack_into_slice(&mut transfer_auditor_info.data.borrow_mut());

    Ok(())
}

/// Processes an [CreateAccount] instruction.
fn process_create_account(accounts: &[AccountInfo], elgaml_pk: ElGamalPK) -> ProgramResult {
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
        get_confidential_address_with_seed(&token_account.mint, &token_account_info.key);
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
        &rent,
        ConfidentialAccount::get_packed_len(),
        &id(),
        system_program_info,
        confidential_account_info,
        confidential_token_account_signer_seeds,
    )?;

    ConfidentialAccount {
        mint: token_account.mint,
        token_account: *token_account_info.key,
        elgaml_pk,
        accept_incoming_transfers: true,
        ..ConfidentialAccount::default()
    }
    .pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes an [CloseAccount] instruction.
fn process_close_account(accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let dest_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (confidential_account, _token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    // TODO: Add real zero balance check
    if confidential_account.pending_balance != ElGamalCT::default()
        || confidential_account.available_balance != ElGamalCT::default()
    {
        msg!("Confidential account balance is not zero");
        return Err(ProgramError::InvalidAccountData);
    }

    let dest_starting_lamports = dest_info.lamports();
    **dest_info.lamports.borrow_mut() = dest_starting_lamports
        .checked_add(confidential_account_info.lamports())
        .ok_or(ProgramError::InvalidAccountData)?;

    **confidential_account_info.lamports.borrow_mut() = 0;
    ConfidentialAccount::default()
        .pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes an [UpdateAccountPk] instruction.
fn process_update_account_pk(
    accounts: &[AccountInfo],
    elgaml_pk: ElGamalPK,
    pending_balance: ElGamalCT,
    available_balance: ElGamalCT,
    new_elgaml_pk: ElGamalPK,
    new_pending_balance: ElGamalCT,
    new_available_balance: ElGamalCT,
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

    // TODO: Balance equality proof....

    if confidential_account.elgaml_pk != elgaml_pk
        || confidential_account.pending_balance != pending_balance
        || confidential_account.available_balance != available_balance
    {
        msg!("Pubkey and/or balance mismatch");
        return Err(ProgramError::InvalidInstructionData);
    }

    confidential_account.elgaml_pk = new_elgaml_pk;
    confidential_account.pending_balance = new_pending_balance;
    confidential_account.available_balance = new_available_balance;
    confidential_account.outbound_transfer = OutboundTransfer::default();

    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes a [Deposit] instruction.
fn process_deposit(accounts: &[AccountInfo], amount: u64, decimals: u8) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let source_token_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let confidential_account_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;
    let signers = account_info_iter.as_slice();

    let (confidential_account, token_account) =
        validate_confidential_account(confidential_account_info, token_account_info)?;

    if token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    if !confidential_account.accept_incoming_transfers {
        msg!("Error: Incoming transfers are disabled");
        return Err(ProgramError::InvalidArgument);
    }

    // Ensure omnibus token account address derivation is correct
    if get_omnibus_token_address(&mint_info.key) != *omnibus_info.key {
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
            &source_token_account_info.key,
            &mint_info.key,
            &omnibus_info.key,
            &owner_info.key,
            signer_pubkeys.as_slice(),
            amount,
            decimals,
        )?,
        &accounts,
    )?;

    // TODO: implement and uncomment the ElGamalCT addition
    //confidential_account.pending_balance += GroupEncoding::encode(amount)

    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes a [Withdraw] instruction.
fn process_withdraw(accounts: &[AccountInfo], amount: u64, decimals: u8) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let dest_token_account_info = next_account_info(account_info_iter)?;
    let omnibus_info = next_account_info(account_info_iter)?;
    let mint_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let owner_info = next_account_info(account_info_iter)?;

    let (confidential_account, token_account) = validate_confidential_account_is_signer(
        confidential_account_info,
        token_account_info,
        owner_info,
        account_info_iter.as_slice(),
    )?;

    if token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    // Ensure omnibus token account address derivation is correct
    let (omnibus_token_address, omnibus_token_bump_seed) =
        get_omnibus_token_address_with_seed(&mint_info.key);
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
            &omnibus_info.key,
            &mint_info.key,
            &dest_token_account_info.key,
            &omnibus_info.key,
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

    // TODO: implement and uncomment the ElGamalCT addition
    //confidential_account.available_balance -= GroupEncoding::encode(amount)

    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes a [SubmitTransferProof] instruction.
fn process_submit_transfer_proof(
    accounts: &[AccountInfo],
    receiver_pk: ElGamalPK,
    receiver_pending_balance: ElGamalCT,
    transfer_proof: TransferProof,
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

    let mut outbound_transfer = &mut confidential_account.outbound_transfer;
    if outbound_transfer.receiver_pk != receiver_pk
        || outbound_transfer.receiver_pending_balance != receiver_pending_balance
    {
        *outbound_transfer = OutboundTransfer::default();
    }

    let (sender_available_balance, sender_transfer_amount, receiver_transfer_amount) =
        match transfer_proof {
            TransferProof::CiphertextValidity(_) => {
                // TODO: Validate the proof and extract the transfer amounts
                outbound_transfer.validity_proof = true;
                (
                    ElGamalCT::default(),
                    ElGamalCT::default(),
                    ElGamalCT::default(),
                )
            }
            TransferProof::Range(_) => {
                // TODO: Validate the proof and extract the transfer amounts
                outbound_transfer.range_proof = true;
                (
                    ElGamalCT::default(),
                    ElGamalCT::default(),
                    ElGamalCT::default(),
                )
            }
        };

    if sender_available_balance != confidential_account.available_balance {
        msg!("Error: Available balance mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    outbound_transfer.sender_transfer_amount = sender_transfer_amount;
    outbound_transfer.receiver_pk = receiver_pk;
    outbound_transfer.receiver_pending_balance = receiver_pending_balance;
    outbound_transfer.receiver_transfer_amount = receiver_transfer_amount;

    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes a [Transfer] instruction.
fn process_transfer(
    accounts: &[AccountInfo],
    receiver_pk: ElGamalPK,
    receiver_transfer_amount: ElGamalCT,
    transfer_auditor_pk: Option<ElGamalPK>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();

    let confidential_account_info = next_account_info(account_info_iter)?;
    let token_account_info = next_account_info(account_info_iter)?;
    let receiver_confidential_account_info = next_account_info(account_info_iter)?;
    let receiver_token_account_info = next_account_info(account_info_iter)?;
    let transfer_auditor_info = next_account_info(account_info_iter)?;

    validate_account_owner(transfer_auditor_info, &id())?;

    //let mint = spl_token::state::Mint::unpack(&mint_info.data.borrow())?;
    let transfer_auditor =
        state::TransferAuditor::unpack_from_slice(&transfer_auditor_info.data.borrow())?;

    if transfer_auditor.transfer_auditor_pk != transfer_auditor_pk {
        msg!("Error: Transfer auditor mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    let (mut confidential_account, token_account) =
        validate_confidential_account(confidential_account_info, token_account_info)?;

    let (receiver_confidential_account, receiver_token_account) = validate_confidential_account(
        receiver_confidential_account_info,
        receiver_token_account_info,
    )?;

    if token_account.mint != receiver_token_account.mint
        || token_account.mint != transfer_auditor.mint
    {
        msg!("Error: Mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if token_account.is_frozen() || receiver_token_account.is_frozen() {
        msg!("Error: Account frozen");
        return Err(ProgramError::InvalidAccountData);
    }

    if !receiver_confidential_account.accept_incoming_transfers {
        msg!("Error: Incoming transfers are disabled");
        return Err(ProgramError::InvalidArgument);
    }

    let outbound_transfer = &confidential_account.outbound_transfer;
    if !(outbound_transfer.validity_proof && outbound_transfer.range_proof) {
        msg!("Error: Transfer proof(s) missing");
        return Err(ProgramError::InvalidAccountData);
    }

    if outbound_transfer.receiver_pk != receiver_pk
        || receiver_confidential_account.elgaml_pk != receiver_pk
    {
        msg!("Error: Receiver public key mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if outbound_transfer.receiver_transfer_amount != receiver_transfer_amount {
        msg!("Error: Transfer amount mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    if outbound_transfer.receiver_pending_balance != receiver_confidential_account.pending_balance {
        msg!("Error: Receiver pending balance mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    // TODO: implement and uncomment the ElGamalCT addition
    // confidential_account.available_balance -= outbound_transfer.sender_transfer_amount;
    // receiver_confidential_account.pending_balance += outbound_transfer.receiver_transfer_amount;

    confidential_account.outbound_transfer = OutboundTransfer::default();

    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    receiver_confidential_account
        .pack_into_slice(&mut receiver_confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes an [ApplyPendingBalance] instruction.
fn process_apply_pending_balance(accounts: &[AccountInfo]) -> ProgramResult {
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

    // TODO: implement and uncomment the ElGamalCT addition
    // confidential_account.available_balance += confidential_account.pending_balance;
    confidential_account.pending_balance = ElGamalCT::default();

    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

/// Processes an [EnableInboundTransfers] or [DisableInboundTransfers] instruction.
fn process_enable_disable_inbound_transfers(
    accounts: &[AccountInfo],
    accept_incoming_transfers: bool,
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

    confidential_account.accept_incoming_transfers = accept_incoming_transfers;
    confidential_account.pack_into_slice(&mut confidential_account_info.data.borrow_mut());
    Ok(())
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    match ConfidentialTokenInstruction::unpack_from_slice(input)? {
        ConfidentialTokenInstruction::ConfigureMint {
            transfer_auditor_pk,
        } => {
            msg!("ConfigureMint");
            process_configure_mint(accounts, transfer_auditor_pk)
        }
        ConfidentialTokenInstruction::UpdateTransferAuditor {
            new_transfer_auditor_pk,
        } => {
            msg!("UpdateTransferAuditor");
            process_update_transfer_auditor(accounts, new_transfer_auditor_pk)
        }
        ConfidentialTokenInstruction::CreateAccount { elgaml_pk } => {
            msg!("CreateAccount");
            process_create_account(accounts, elgaml_pk)
        }
        ConfidentialTokenInstruction::CloseAccount {
            crypto_empty_balance_proof: _, /* TODO */
        } => {
            msg!("CloseAccount");
            process_close_account(accounts)
        }
        ConfidentialTokenInstruction::UpdateAccountPk {
            elgaml_pk,
            pending_balance,
            available_balance,
            new_elgaml_pk,
            new_pending_balance,
            new_available_balance,
            crypto_balance_equality_proof: _, /* TODO */
        } => {
            msg!("UpdateAccountPk");
            process_update_account_pk(
                accounts,
                elgaml_pk,
                pending_balance,
                available_balance,
                new_elgaml_pk,
                new_pending_balance,
                new_available_balance,
            )
        }
        ConfidentialTokenInstruction::Deposit { amount, decimals } => {
            msg!("Deposit");
            process_deposit(accounts, amount, decimals)
        }
        ConfidentialTokenInstruction::Withdraw {
            amount,
            decimals,
            crypto_sufficient_balance_proof: _, /* TODO */
        } => {
            msg!("Withdraw");
            process_withdraw(accounts, amount, decimals)
        }
        ConfidentialTokenInstruction::SubmitTransferProof {
            receiver_pk,
            receiver_pending_balance,
            transfer_proof,
        } => {
            msg!("SubmitTransferProof");
            process_submit_transfer_proof(
                accounts,
                receiver_pk,
                receiver_pending_balance,
                transfer_proof,
            )
        }
        ConfidentialTokenInstruction::Transfer {
            receiver_pk,
            receiver_transfer_split_amount: _, /* TODO */
            transfer_audit,
        } => {
            msg!("Transfer");

            // TODO: Ensure the proof in `transfer_audit` is valid

            // TODO: use `combine_u32_ciphertexts()`...
            /*
            let receiver_transfer_amount = combine_u32_ciphertexts(
                receiver_transfer_split_amount.0,
                receiver_transfer_split_amount.1,
            );
            */
            let receiver_transfer_amount = ElGamalCT::default();

            process_transfer(
                accounts,
                receiver_pk,
                receiver_transfer_amount,
                transfer_audit.map(|ta| ta.0),
            )
        }
        ConfidentialTokenInstruction::ApplyPendingBalance => {
            msg!("ApplyPendingBalance");
            process_apply_pending_balance(accounts)
        }
        ConfidentialTokenInstruction::DisableInboundTransfers => {
            msg!("DisableInboundTransfers");
            process_enable_disable_inbound_transfers(accounts, false)
        }
        ConfidentialTokenInstruction::EnableInboundTransfers => {
            msg!("EnableInboundTransfers");
            process_enable_disable_inbound_transfers(accounts, true)
        }
    }
}
