//! Program instructions
//!

#[cfg(not(target_arch = "bpf"))]
use spl_zk_token_sdk::encryption::elgamal::ElGamalPubkey;
use {
    crate::{pod::*, *},
    bytemuck::{Pod, Zeroable},
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive, ToPrimitive},
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::Pubkey,
        sysvar,
    },
    spl_zk_token_sdk::zk_token_elgamal::pod,
};

pub use spl_zk_token_sdk::zk_token_proof_instruction::*;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct ConfigureMintInstructionData {
    /// The `transfer_auditor` public key.
    pub transfer_auditor_pk: pod::ElGamalPubkey,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct UpdateTransferAuditorInstructionData {
    /// The new `transfer_auditor` public key.
    pub new_transfer_auditor_pk: pod::ElGamalPubkey,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CreateAccountInstructionData {
    /// The public key associated with the account
    pub elgamal_pk: pod::ElGamalPubkey,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct DepositInstructionData {
    /// The amount of tokens to deposit
    pub amount: PodU64,
    /// Expected number of base 10 digits to the right of the decimal place.
    pub decimals: u8,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawInstructionData {
    /// The amount of tokens to withdraw
    pub amount: PodU64,
    /// Expected number of base 10 digits to the right of the decimal place.
    pub decimals: u8,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyPendingBalanceData {
    /// Counts the number of incoming transfers since the last successful `ApplyPendingBalance`
    /// instruction
    pub expected_incoming_transfer_count: PodU64,
}

#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum ConfidentialTokenInstruction {
    /// Configures confidential transfers for a given SPL Token mint
    ///
    /// This instruction:
    /// * Creates the omnibus account that will be used to store all SPL Tokens deposited into the
    ///   confidential accounts this mint.
    /// * Creates the TransferAuditor account.
    ///
    /// If the SPL Token has a freeze authority configured, the freeze authority must be a signer
    /// and a transfer auditor may be optionally configured.  Otherwise this instruction requires
    /// no signers, and a transfer auditor is cannot be configured.
    ///
    /// The instruction fails if the confidential transfers are already configured for the mint.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writeable,signer]` Funding account (must be a system account)
    ///   1. `[]` The SPL Token mint account to enable confidential transfers on
    ///   2. `[writable]` The omnibus SPL Token account to create, computed by `get_omnibus_token_address()`
    ///   3. `[writable]` The TransferAuditor account to create, computed by `get_transfer_auditor_address()`
    ///   4. `[]` System program
    ///   5. `[]` SPL Token program
    ///   6. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   7. `[signer]` (optional) The SPL Token mint freeze authority if not `None`
    ///
    //
    /// Data expected by this instruction:
    ///   `ConfigureMintInstructionData` (optional) if not provided then the transfer auditor is
    ///   permanently disabled for this SPL Token mint
    ///
    ConfigureMint,

    /// Updates the transfer auditor ElGamal public key.
    /// This instruction fails if a transfer auditor is currently `None` for this Token mint.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The TransferAuditor account, computed by `get_transfer_auditor_address()`
    ///   1. `[]` The SPL Token mint account
    ///   2. `[signer]` The single SPL Token Mint freeze authority
    /// or:
    ///   2. `[]` The multisig SPL Token freeze authority.
    ///   3.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `UpdateTransferAuditorInstructionData` (optional) if not provided then the transfer auditor is
    ///   permanently disabled for this SPL Token mint
    ///
    UpdateTransferAuditor,

    /// Create a confidential token account
    ///
    /// This is a PDA, derived from the token mint and linked token account. Ownership is held in
    /// the linked SPL Token account. The new account will be rent-exempt.
    ///
    /// The instruction fails if the confidential token account already exists.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writeable,signer]` Funding account for rent (must be a system account)
    ///   1. `[writable]` The new confidential token account to create, as computed by `get_confidential_token_address()`
    ///   2. `[]` Corresponding SPL Token account
    ///   3. `[]` System program
    ///   4. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   5. `[signer]` The single source account owner
    /// or:
    ///   5. `[]` The multisig source account owner
    ///   6.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `CreateAccountInstructionData`
    ///
    CreateAccount,

    /// Close a confidential token account by transferring all lamports it holds to the reclaim
    /// account. The account must not hold any confidential tokens in its pending or available
    /// balances. Use `DisableInboundTransfers` to block inbound transfers first if necessary.
    ///
    ///   0. `[writable]` The CToken account to close
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[writable]` The reclaim account
    ///   3. `[]` Instructions sysvar
    ///   4. `[signer]` The single account owner
    /// or:
    ///   4. `[]` The multisig account owner
    ///   5.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    /// The preceding instruction must be ProofInstruction::VerifyCloseAccount.
    ///
    CloseAccount,

    /// Update the confidential token account's ElGamal public key.
    ///
    /// This instruction will fail the pending balance is not empty, so invoking
    /// `ApplyPendingBalance` first is recommended.
    ///
    /// If the account is heavily used, consider invoking `DisableInboundTransfers` in a separate
    /// transaction first to avoid new inbound transfers from causing this instruction to fail.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account to update
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[]` Instructions sysvar
    ///   3. `[signer]` The single account owner
    /// or:
    ///   3. `[]` The multisig account owner
    ///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    /// The preceding instruction must be ProofInstruction::VerifyUpdateAccountPk.
    ///
    UpdateAccountPk,

    /// Deposit SPL Tokens into the pending balance of a confidential token account.
    ///
    /// The account owner can then invoke the `ApplyPendingBalance` instruction to roll the deposit
    /// into their available balance at a time of their choosing.
    ///
    /// Fails if the source or destination accounts are frozen.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The source SPL Token account
    ///   1. `[writable]` The destination confidential token account
    ///   2. `[]` The destination's corresponding SPL Token account
    ///   3. `[writable]` The omnibus SPL Token account for this token mint, computed by `get_omnibus_token_address()`
    ///   4. `[]` The token mint.
    ///   5. `[]` SPL Token program
    ///   6. `[signer]` The single source account owner or delegate
    /// or:
    ///   6. `[]` The multisig source account owner or delegate.
    ///   7.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `DepositInstructionData`
    ///
    Deposit,

    /// Withdraw SPL Tokens from the available balance of a confidential token account.
    ///
    /// Fails if the source or destination accounts are frozen.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL token account
    ///   2. `[writable]` The destination SPL Token account
    ///   3. `[]` The token mint.
    ///   4. `[writable]` The omnibus SPL Token account for this token mint, computed by `get_omnibus_token_address()`
    ///   5. `[]` SPL Token program
    ///   6. `[]` Instructions sysvar
    ///   7. `[signer]` The single source account owner
    /// or:
    ///   7. `[]` The multisig  source account owner
    ///   8.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `WithdrawInstructionData`
    ///
    /// The preceding instruction must be ProofInstruction::VerifyWithdraw.
    ///
    Withdraw,

    /// Transfer tokens confidentially.
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source SPL Token account
    ///   2. `[writeable]` The destination confidential token account
    ///   3. `[]` The destination token account
    ///   4. `[]` The TransferAuditor account, computed by `get_transfer_auditor_address()`
    ///   5. `[]` Instructions sysvar
    ///   6. `[signer]` The single source account owner
    /// or:
    ///   5. `[]` The multisig  source account owner
    ///   6.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    /// The preceding instruction must be ProofInstruction::VerifyTransfer.
    ///
    Transfer,

    /// Applies the pending balance to the available balance then clears the pending balance.
    ///
    /// Account expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[signer]` The single account owner
    /// or:
    ///   2. `[]` The multisig account owner
    ///   3.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `ApplyPendingBalanceData` (optional) if the client wishes to assert the number of
    ///   processed incoming transfers
    ///
    ApplyPendingBalance,

    /// Disable incoming transfers to a confidential token account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[signer]` The single account owner
    /// or:
    ///   2. `[]` The multisig account owner
    ///   3.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    DisableInboundTransfers,

    /// Enable incoming transfers for a confidential token account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[signer]` The single account owner
    /// or:
    ///   2. `[]` The multisig account owner
    ///   3.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    EnableInboundTransfers,
}

pub(crate) fn decode_instruction_type(
    input: &[u8],
) -> Result<ConfidentialTokenInstruction, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        FromPrimitive::from_u8(input[0]).ok_or(ProgramError::InvalidInstructionData)
    }
}

pub(crate) fn decode_instruction_data<T: Pod>(input: &[u8]) -> Result<&T, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        pod_from_bytes(&input[1..]).ok_or(ProgramError::InvalidArgument)
    }
}

pub(crate) fn decode_optional_instruction_data<T: Pod>(
    input: &[u8],
) -> Result<Option<&T>, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        pod_maybe_from_bytes(&input[1..])
    }
}

pub(crate) fn encode_instruction<T: Pod>(
    accounts: Vec<AccountMeta>,
    instruction_type: ConfidentialTokenInstruction,
    instruction_data: &T,
) -> Instruction {
    let mut data = vec![ToPrimitive::to_u8(&instruction_type).unwrap()];
    data.extend_from_slice(bytemuck::bytes_of(instruction_data));
    Instruction {
        program_id: id(),
        accounts,
        data,
    }
}

fn _configure_mint(
    funding_address: Pubkey,
    token_mint_address: Pubkey,
    transfer_auditor_pk_and_freeze_authority: Option<(pod::ElGamalPubkey, Pubkey)>,
) -> Instruction {
    let omnibus_token_address = get_omnibus_token_address(&token_mint_address);
    let transfer_auditor_address = get_transfer_auditor_address(&token_mint_address);

    let mut accounts = vec![
        AccountMeta::new(funding_address, true),
        AccountMeta::new_readonly(token_mint_address, false),
        AccountMeta::new(omnibus_token_address, false),
        AccountMeta::new(transfer_auditor_address, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    if let Some((transfer_auditor_pk, freeze_authority)) = transfer_auditor_pk_and_freeze_authority
    {
        accounts.push(AccountMeta::new(freeze_authority, true));
        encode_instruction(
            accounts,
            ConfidentialTokenInstruction::ConfigureMint,
            &ConfigureMintInstructionData {
                transfer_auditor_pk,
            },
        )
    } else {
        encode_instruction(accounts, ConfidentialTokenInstruction::ConfigureMint, &())
    }
}

/// Create a `ConfigureMint` instruction
pub fn configure_mint(funding_address: Pubkey, token_mint_address: Pubkey) -> Instruction {
    _configure_mint(funding_address, token_mint_address, None)
}

/// Create a `ConfigureMint` instruction with a transfer auditor
pub fn configure_mint_with_transfer_auditor(
    funding_address: Pubkey,
    token_mint_address: Pubkey,
    transfer_auditor_pk: pod::ElGamalPubkey,
    freeze_authority: Pubkey,
) -> Instruction {
    _configure_mint(
        funding_address,
        token_mint_address,
        Some((transfer_auditor_pk, freeze_authority)),
    )
}

/// Create a `CreateAccount` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn create_account(
    funding_address: Pubkey,
    zk_token_account: Pubkey,
    elgamal_pk: ElGamalPubkey,
    token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(funding_address, true),
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![encode_instruction(
        accounts,
        ConfidentialTokenInstruction::CreateAccount,
        &CreateAccountInstructionData {
            elgamal_pk: elgamal_pk.into(),
        },
    )]
}

/// Create a `CloseAccount` instruction
pub fn close_account(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    reclaim_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    proof_data: CloseAccountData,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new(reclaim_account, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![
        ProofInstruction::VerifyCloseAccount.encode(&proof_data),
        encode_instruction(accounts, ConfidentialTokenInstruction::CloseAccount, &()),
    ]
}

/// Create a `UpdateAccountPk` instruction
pub fn update_account_pk(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    proof_data: UpdateAccountPkData,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![
        ProofInstruction::VerifyUpdateAccountPk.encode(&proof_data),
        encode_instruction(accounts, ConfidentialTokenInstruction::UpdateAccountPk, &()),
    ]
}

/// Create a `Deposit` instruction
#[allow(clippy::too_many_arguments)]
pub fn deposit(
    source_token_account: Pubkey,
    mint: &Pubkey,
    destination_zk_token_account: Pubkey,
    destination_token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    amount: u64,
    decimals: u8,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(source_token_account, false),
        AccountMeta::new(destination_zk_token_account, false),
        AccountMeta::new_readonly(destination_token_account, false),
        AccountMeta::new(get_omnibus_token_address(mint), false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![encode_instruction(
        accounts,
        ConfidentialTokenInstruction::Deposit,
        &DepositInstructionData {
            amount: amount.into(),
            decimals,
        },
    )]
}

/// Create a `Withdraw` instruction
#[allow(clippy::too_many_arguments)]
pub fn withdraw(
    source_zk_token_account: Pubkey,
    source_token_account: Pubkey,
    destination_token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    amount: u64,
    decimals: u8,
    proof_data: WithdrawData,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(source_zk_token_account, false),
        AccountMeta::new_readonly(source_token_account, false),
        AccountMeta::new(destination_token_account, false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new(get_omnibus_token_address(mint), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![
        ProofInstruction::VerifyWithdraw.encode(&proof_data),
        encode_instruction(
            accounts,
            ConfidentialTokenInstruction::Withdraw,
            &WithdrawInstructionData {
                amount: amount.into(),
                decimals,
            },
        ),
    ]
}

/// Create a `Transfer` instruction
#[allow(clippy::too_many_arguments)]
pub fn transfer(
    source_zk_token_account: Pubkey,
    source_token_account: Pubkey,
    destination_zk_token_account: Pubkey,
    destination_token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    transfer_data: TransferData,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(source_zk_token_account, false),
        AccountMeta::new_readonly(source_token_account, false),
        AccountMeta::new(destination_zk_token_account, false),
        AccountMeta::new_readonly(destination_token_account, false),
        AccountMeta::new(get_transfer_auditor_address(mint), false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![
        ProofInstruction::VerifyTransfer.encode(&transfer_data),
        encode_instruction(accounts, ConfidentialTokenInstruction::Transfer, &()),
    ]
}

/// Create a `ApplyPendingBalance` instruction
pub fn apply_pending_balance(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    expected_incoming_transfer_count: Option<u64>,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    if let Some(expected_incoming_transfer_count) = expected_incoming_transfer_count {
        vec![encode_instruction(
            accounts,
            ConfidentialTokenInstruction::ApplyPendingBalance,
            &ApplyPendingBalanceData {
                expected_incoming_transfer_count: expected_incoming_transfer_count.into(),
            },
        )]
    } else {
        vec![encode_instruction(
            accounts,
            ConfidentialTokenInstruction::ApplyPendingBalance,
            &(),
        )]
    }
}
