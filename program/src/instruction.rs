//! Program instructions
//!

#[cfg(not(target_arch = "bpf"))]
use solana_zk_token_sdk::encryption::{auth_encryption::AeCiphertext, elgamal::ElGamalPubkey};
pub use solana_zk_token_sdk::zk_token_proof_instruction::*;
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
    solana_zk_token_sdk::zk_token_elgamal::pod,
};

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ConfigureAccountInstructionData {
    /// The public key associated with the account
    pub elgamal_pk: pod::ElGamalPubkey,
    /// The decryptable balance (always 0) once the configure account succeeds
    pub decryptable_zero_balance: pod::AeCiphertext,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CloseInstructionData {
    /// Relative location of the `ProofInstruction::VerifyCloseAccount` instruction to the
    /// `CloseAccount` instruction in the transaction
    pub proof_instruction_offset: i8,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct DepositInstructionData {
    /// The amount of tokens to deposit
    pub amount: PodU64,
    /// Expected number of base 10 digits to the right of the decimal place
    pub decimals: u8,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawInstructionData {
    /// The amount of tokens to withdraw
    pub amount: PodU64,
    /// Expected number of base 10 digits to the right of the decimal place
    pub decimals: u8,
    /// The new decryptable balance if the withrawal succeeds
    pub new_decryptable_available_balance: pod::AeCiphertext,
    /// Relative location of the `ProofInstruction::VerifyWithdraw` instruction to the `Withdraw`
    /// instruction in the transaction
    pub proof_instruction_offset: i8,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferInstructionData {
    /// The new source decryptable balance if the transfer succeeds
    pub new_source_decryptable_available_balance: pod::AeCiphertext,
    /// Relative location of the `ProofInstruction::VerifyTransfer` instruction to the
    /// `Transfer` instruction in the transaction
    pub proof_instruction_offset: i8,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyPendingBalanceData {
    /// The expected number of pending balance credits since the last successful
    /// `ApplyPendingBalance` instruction
    pub expected_pending_balance_credit_counter: PodU64,
    /// The new decryptable balance if the pending balance is applied successfully
    pub new_decryptable_available_balance: pod::AeCiphertext,
}

#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum ZkTokenInstruction {
    /// Configures confidential transfers for a given SPL Token mint
    ///
    /// This instruction:
    /// * Creates the omnibus account that will be used to store all SPL Tokens deposited into the
    ///   confidential accounts for this mint.
    /// * Creates the confidential mint
    ///
    /// If the SPL Token has a freeze authority configured, the freeze authority must be a signer
    /// and an auditor may be optionally configured.  Otherwise this instruction requires
    /// no signers, and an auditor cannot be configured.
    ///
    /// The instruction fails if the confidential transfers are already configured for the mint.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writeable,signer]` Funding account (must be a system account)
    ///   1. `[]` The SPL Token mint account to enable confidential transfers on
    ///   2. `[writable]` The omnibus SPL Token account to create, computed by `get_omnibus_token_address()`
    ///   3. `[writable]` The confidential mint to create, computed by `get_zk_mint_address()`
    ///   4. `[]` System program
    ///   5. `[]` SPL Token program
    ///   6. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   7. `[signer]` (optional) The single SPL Token mint freeze authority if not `None`
    /// or:
    ///   7. `[]` (optional) The multisig SPL Token freeze authority if not `None`
    ///   8.. `[signer]` (optional) Required M signer accounts for the SPL Token Multisig account
    ///
    //
    /// Data expected by this instruction:
    ///   `state::Auditor` (optional) auditor details may only be specified when the SPL Token mint
    ///   freeze authority is not `None`
    ///
    ConfigureMint,

    /// Updates the auditor ElGamal public key.
    /// This instruction fails if the SPL Token mint freeze authority is `None` or if the auditor
    /// has been disabled.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential mint, computed by `get_zk_mint_address()`
    ///   1. `[]` The SPL Token mint
    ///   2. `[signer]` The single SPL Token Mint freeze authority
    /// or:
    ///   2. `[]` The multisig SPL Token freeze authority.
    ///   3.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `state::Auditor`
    ///
    UpdateAuditor,

    /// Configures confidential transfers for a given SPL Token account
    ///
    /// This is a PDA, derived from the token mint and linked token account. Ownership is held in
    /// the linked SPL Token account. The new account will be rent-exempt.
    ///
    /// The instruction fails if the confidential token account already exists.
    ///
    /// Deposits and transfers are disabled by default, use the `EnableBalanceCredits` instruction
    /// to enable them.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writeable,signer]` Funding account for rent (must be a system account)
    ///   1. `[writable]` The new confidential token account to create, as computed by `get_zk_token_address()`
    ///   2. `[]` Corresponding SPL Token account
    ///   3. `[]` System program
    ///   4. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   5. `[signer]` The single source account owner
    /// or:
    ///   5. `[]` The multisig source account owner
    ///   6.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `ConfigureAccountInstructionData`
    ///
    ConfigureAccount,

    /// Close a confidential token account by transferring all lamports it holds to the reclaim
    /// account. The account must not hold any confidential tokens in its pending or available
    /// balances. Use `DisableBalanceCredits` to block balance credits first if necessary.
    ///
    ///   0. `[writable]` The confidential token account to close
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[writable]` The reclaim account
    ///   3. `[]` Instructions sysvar
    ///   4. `[signer]` The single account owner
    /// or:
    ///   4. `[]` The multisig account owner
    ///   5.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `CloseInstructionData`
    ///
    /// The preceding instruction must be ProofInstruction::VerifyCloseAccount.
    ///
    CloseAccount,

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
    ///   4. `[]` The confidential mint, computed by `get_zk_mint_address()`
    ///   5. `[]` Instructions sysvar
    ///   6. `[signer]` The single source account owner
    /// or:
    ///   5. `[]` The multisig  source account owner
    ///   6.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `TransferInstructionData`
    ///
    /// The preceding instruction must be ProofInstruction::VerifyTransfer.
    ///
    Transfer,

    /// Applies the pending balance to the available balance, based on the history of `Deposit`
    /// and/or `Transfer` instructions.
    ///
    /// After submitting `ApplyPendingBalance`, the client should compare
    /// `ZkAccount::expected_pending_balance_credit_counter` with
    /// `ZkAccount::actual_applied_pending_balance_instructions`.  If they are equal then the
    /// `ZkAccount::decryptable_available_balance` is consistent with
    /// `ZkAccount::available_balance`. If they differ then there is more pending
    /// balance to be applied.
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
    ///   processed instructions that affect the pending balance
    ///
    ApplyPendingBalance,

    /// Enable `Deposit` and `Transfer` instructions for the given confidential token account.
    ///
    /// The required authority for this instruction is conditional on the value of the
    /// `ZkMint::auditor::enable_balance_credits_authority` field.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[]` The confidential mint, computed by `get_zk_mint_address()`
    ///   3. `[signer]` Single authority
    /// or:
    ///   3. `[]` Multisig authority
    ///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    EnableBalanceCredits,

    /// Disable `Deposit` and `Transfer` instructions for the given confidential token account.
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
    DisableBalanceCredits,
}

pub fn decode_instruction_type(input: &[u8]) -> Result<ZkTokenInstruction, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        FromPrimitive::from_u8(input[0]).ok_or(ProgramError::InvalidInstructionData)
    }
}

pub fn decode_instruction_data<T: Pod>(input: &[u8]) -> Result<&T, ProgramError> {
    if input.is_empty() {
        Err(ProgramError::InvalidInstructionData)
    } else {
        pod_from_bytes(&input[1..]).ok_or(ProgramError::InvalidArgument)
    }
}

#[allow(dead_code)]
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
    instruction_type: ZkTokenInstruction,
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

/// Create a `ConfigureMint` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn configure_mint(
    funding_address: Pubkey,
    mint: Pubkey,
    freeze_authority: Option<Pubkey>,
    freeze_authority_multisig_signers: &[&Pubkey],
    auditor: Option<state::Auditor>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(funding_address, true),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(get_omnibus_token_address(&mint), false),
        AccountMeta::new(get_zk_mint_address(&mint), false),
        AccountMeta::new_readonly(solana_program::system_program::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    if let Some(freeze_authority) = freeze_authority {
        accounts.push(AccountMeta::new(
            freeze_authority,
            freeze_authority_multisig_signers.is_empty(),
        ));
        for multisig_signer in freeze_authority_multisig_signers.iter() {
            accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
        }
    }

    //let auditor = auditor.unwrap_or_else(|| state::Auditor::zeroed());
    let auditor = auditor.unwrap_or_else(state::Auditor::zeroed);
    encode_instruction(accounts, ZkTokenInstruction::ConfigureMint, &auditor)
}

/// Create an `UpdateAuditor` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn update_auditor(
    mint: Pubkey,
    freeze_authority: Pubkey,
    freeze_authority_multisig_signers: &[&Pubkey],
    auditor_pk: Option<ElGamalPubkey>,
    enable_balance_credits_authority: Option<Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(get_zk_mint_address(&mint), false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(
            freeze_authority,
            freeze_authority_multisig_signers.is_empty(),
        ),
    ];

    for multisig_signer in freeze_authority_multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    let auditor_pk = auditor_pk.unwrap_or_default();
    let enable_balance_credits_authority = enable_balance_credits_authority.unwrap_or_default();
    encode_instruction(
        accounts,
        ZkTokenInstruction::UpdateAuditor,
        &state::Auditor {
            enable_balance_credits_authority,
            auditor_pk: auditor_pk.into(),
        },
    )
}

/// Create a `ConfigureAccount` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn configure_account(
    funding_address: Pubkey,
    zk_token_account: Pubkey,
    elgamal_pk: ElGamalPubkey,
    decryptable_zero_balance: AeCiphertext,
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
        ZkTokenInstruction::ConfigureAccount,
        &ConfigureAccountInstructionData {
            elgamal_pk: elgamal_pk.into(),
            decryptable_zero_balance: decryptable_zero_balance.into(),
        },
    )]
}

/// Create a `EnableBalanceCredits` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn enable_balance_credits(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(get_zk_mint_address(mint), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![encode_instruction(
        accounts,
        ZkTokenInstruction::EnableBalanceCredits,
        &(),
    )]
}

/// Create a `DisableBalanceCredits` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn disable_balance_credits(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![encode_instruction(
        accounts,
        ZkTokenInstruction::DisableBalanceCredits,
        &(),
    )]
}

/// Create an inner `CloseAccount` instruction
///
/// This instruction is suitable for use with a cross-program `invoke` provided that the previous
/// instruction is `ProofInstruction::VerifyCloseAccount`
pub fn inner_close_account(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    reclaim_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    proof_instruction_offset: i8,
) -> Instruction {
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

    encode_instruction(
        accounts,
        ZkTokenInstruction::CloseAccount,
        &CloseInstructionData {
            proof_instruction_offset,
        },
    )
}

/// Create a `CloseAccount` instruction
pub fn close_account(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    reclaim_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    proof_data: &CloseAccountData,
) -> Vec<Instruction> {
    vec![
        verify_close_account(proof_data),
        inner_close_account(
            zk_token_account,
            token_account,
            reclaim_account,
            authority,
            multisig_signers,
            -1,
        ),
    ]
}

/// Create a `Deposit` instruction
#[allow(clippy::too_many_arguments)]
pub fn deposit(
    source_token_account: Pubkey,
    mint: Pubkey,
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
        AccountMeta::new(get_omnibus_token_address(&mint), false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![encode_instruction(
        accounts,
        ZkTokenInstruction::Deposit,
        &DepositInstructionData {
            amount: amount.into(),
            decimals,
        },
    )]
}

/// Create a inner `Withdraw` instruction
///
/// This instruction is suitable for use with a cross-program `invoke` provided that the previous
/// instruction is `ProofInstruction::VerifyWithdraw`
#[allow(clippy::too_many_arguments)]
pub fn inner_withdraw(
    source_zk_token_account: Pubkey,
    source_token_account: Pubkey,
    destination_token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    amount: u64,
    decimals: u8,
    new_decryptable_available_balance: pod::AeCiphertext,
    proof_instruction_offset: i8,
) -> Instruction {
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

    encode_instruction(
        accounts,
        ZkTokenInstruction::Withdraw,
        &WithdrawInstructionData {
            amount: amount.into(),
            decimals,
            new_decryptable_available_balance,
            proof_instruction_offset,
        },
    )
}

/// Create a `Withdraw` instruction
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_arch = "bpf"))]
pub fn withdraw(
    source_zk_token_account: Pubkey,
    source_token_account: Pubkey,
    destination_token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    amount: u64,
    decimals: u8,
    new_decryptable_available_balance: AeCiphertext,
    proof_data: &WithdrawData,
) -> Vec<Instruction> {
    vec![
        verify_withdraw(proof_data),
        inner_withdraw(
            source_zk_token_account,
            source_token_account,
            destination_token_account,
            mint,
            authority,
            multisig_signers,
            amount,
            decimals,
            new_decryptable_available_balance.into(),
            -1,
        ),
    ]
}

/// Create a inner `Transfer` instruction
///
/// This instruction is suitable for use with a cross-program `invoke` provided that the previous
/// instruction is `ProofInstruction::VerifyTransfer`
#[allow(clippy::too_many_arguments)]
pub fn inner_transfer(
    source_zk_token_account: Pubkey,
    source_token_account: Pubkey,
    destination_zk_token_account: Pubkey,
    destination_token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    new_source_decryptable_available_balance: pod::AeCiphertext,
    proof_instruction_offset: i8,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(source_zk_token_account, false),
        AccountMeta::new_readonly(source_token_account, false),
        AccountMeta::new(destination_zk_token_account, false),
        AccountMeta::new_readonly(destination_token_account, false),
        AccountMeta::new_readonly(get_zk_mint_address(mint), false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    encode_instruction(
        accounts,
        ZkTokenInstruction::Transfer,
        &TransferInstructionData {
            new_source_decryptable_available_balance,
            proof_instruction_offset,
        },
    )
}

/// Create a `Transfer` instruction
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_arch = "bpf"))]
pub fn transfer(
    source_zk_token_account: Pubkey,
    source_token_account: Pubkey,
    destination_zk_token_account: Pubkey,
    destination_token_account: Pubkey,
    mint: &Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    new_source_decryptable_available_balance: AeCiphertext,
    proof_data: &TransferData,
) -> Vec<Instruction> {
    vec![
        verify_transfer(proof_data),
        inner_transfer(
            source_zk_token_account,
            source_token_account,
            destination_zk_token_account,
            destination_token_account,
            mint,
            authority,
            multisig_signers,
            new_source_decryptable_available_balance.into(),
            -1,
        ),
    ]
}

/// Create a inner `ApplyPendingBalance` instruction
///
/// This instruction is suitable for use with a cross-program `invoke`
#[allow(clippy::too_many_arguments)]
pub fn inner_apply_pending_balance(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    expected_pending_balance_credit_counter: u64,
    new_decryptable_available_balance: pod::AeCiphertext,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    encode_instruction(
        accounts,
        ZkTokenInstruction::ApplyPendingBalance,
        &ApplyPendingBalanceData {
            expected_pending_balance_credit_counter: expected_pending_balance_credit_counter.into(),
            new_decryptable_available_balance,
        },
    )
}

/// Create a `ApplyPendingBalance` instruction
#[cfg(not(target_arch = "bpf"))]
pub fn apply_pending_balance(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    authority: Pubkey,
    multisig_signers: &[&Pubkey],
    pending_balance_instructions: u64,
    new_decryptable_available_balance: AeCiphertext,
) -> Vec<Instruction> {
    vec![inner_apply_pending_balance(
        zk_token_account,
        token_account,
        authority,
        multisig_signers,
        pending_balance_instructions,
        new_decryptable_available_balance.into(),
    )]
}
