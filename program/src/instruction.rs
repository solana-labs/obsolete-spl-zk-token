//! Program instructions

use {
    crate::{pod::*, *},
    bytemuck::Pod,
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive, ToPrimitive},
    solana_program::{
        instruction::{AccountMeta, Instruction},
        program_error::ProgramError,
        pubkey::Pubkey,
        sysvar,
    },
    spl_zk_token_crypto::{instruction::*, pod::*},
    zeroable::Zeroable,
};

pub use spl_zk_token_crypto::instruction::{CloseAccountData, UpdateAccountPkData};

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct ConfigureMintInstructionData {
    /// The `transfer_auditor` public key.
    pub transfer_auditor_pk: PodElGamalPK,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct UpdateTransferAuditorInstructionData {
    /// The new `transfer_auditor` public key.
    pub new_transfer_auditor_pk: PodElGamalPK,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CreateAccountInstructionData {
    /// The public key associated with the account
    pub elgamal_pk: PodElGamalPK,

    /// 0, encrypted with `elgamal_pk`
    pub zero_balance: PodElGamalCT,

    // TODO: Proof that `zero_balance` equals 0
    pub crypto_zero_balance_proof: [u8; 256],
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
    // TODO: Proof that the encrypted balance is >= `amount`
    pub crypto_sufficient_balance_proof: [u8; 256],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct SubmitCiphertextValidityProofInstructionData {
    /// The receiver's ElGamal public key
    pub receiver_pk: PodElGamalPK,

    /// The receiver's pending balance, encrypted with `receiver_pk`
    pub receiver_pending_balance: PodElGamalCT,

    pub proof: TransDataCTValidity,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct SubmitRangeProofInstructionData {
    /// The receiver's ElGamal public key
    pub receiver_pk: PodElGamalPK,

    /// The receiver's pending balance, encrypted with `receiver_pk`
    pub receiver_pending_balance: PodElGamalCT,

    pub proof: TransDataRangeProof,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferInstructionData {
    /// Receiver's encryption key
    pub receiver_pk: PodElGamalPK,

    /// Transfer amount split into two 32 values and encrypted so only the receiver can view it
    pub receiver_transfer_split_amount: ElGamalSplitCT,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferWithAuditorInstructionData {
    pub transfer_data: TransferInstructionData,

    /// Transfer Auditor's encryption key
    pub transfer_auditor_pk: PodElGamalPK,

    /// Transfer amount split into two 32 values and encrypted so only the transfer auditor can view it
    pub transfer_auditor_split_amount: ElGamalSplitCT,

    /// TODO: Proof that `transfer_auditor_split_amount` is equal to `receiver_transfer_split_amount`
    pub crypto_auditor_amount_equality_proof: (),
}

#[derive(Clone, Copy, Debug, Zeroable, FromPrimitive, ToPrimitive)]
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
    ///   7. `[signer]` (optional) The SPL Token mint freeze authority, if not `None`
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

    /// Close a confidential token account by transferring all lamports it holds to the destination
    /// account. The account must not hold any confidential tokens in its pending or available
    /// balances. Use `DisableInboundTransfers` to block inbound transfers first if necessary.
    ///
    ///   0. `[writable]` The CToken account to close
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[writable]` The destination account
    ///   3. `[]` Instructions sysvar
    ///   4. `[signer]` The single account owner
    /// or:
    ///   4. `[]` The multisig account owner
    ///   5.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   None
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
    ///   6. `[signer]` The single source account owner
    /// or:
    ///   6. `[]` The multisig  source account owner
    ///   7.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `WithdrawInstructionData`
    ///
    Withdraw,

    /// Submits a confidential transfer ciphertext validity proof. The two proof submissions required before the
    /// `Transfer` instruction will succeed are `SubmitCiphertextValidityProof` and `SubmitRangeProof`.
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL Token account
    ///   2. `[]` The destination confidential token account
    ///   3. `[signer]` The single source account owner
    /// or:
    ///   3. `[]` The multisig  source account owner
    ///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `SubmitCiphertextValidityProofInstructionData`
    ///
    SubmitCiphertextValidityProof,

    /// Submits a confidential transfer range proof. The two proof submissions required before the
    /// `Transfer` instruction will succeed are `SubmitCiphertextValidityProof` and `SubmitRangeProof`.
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL Token account
    ///   2. `[]` The destination confidential token account
    ///   3. `[signer]` The single source account owner
    /// or:
    ///   3. `[]` The multisig  source account owner
    ///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    /// Data expected by this instruction:
    ///   `SubmitRangeProofInstructionData
    ///
    SubmitRangeProof,

    /// Transfers tokens confidentially from one account to another. The prerequisite transfer
    /// proofs must have already been successfully submitted using `SubmitCiphertextValidityProof`
    /// and `SubmitRangeProof` for this instruction to succeed.
    ///
    /// A transfer will fail if:
    /// * Either the source or the destination is frozen
    /// * The destination has disabled incoming transfers by invoking `DisableInboundTransfers`
    /// * Prerequisite proofs have not been submitted
    /// * The destination received a transfer from another source causing the previously
    ///   submitted transfer proofs for this transfer to be invalidated
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL Token account
    ///   2. `[writable]` The destination confidential token account
    ///   3. `[]` The destination token account
    ///   4. `[]` The TransferAuditor account, computed by `get_transfer_auditor_address()`
    ///
    /// The primary purpose of this instruction is to enable receiver and auditor visibility into a
    /// successful transfer and its balance, which can be determined by inspecting the `Transfer`
    /// instruction data and the status of the encompassing transaction (that is, access to
    /// on-chain account data is not required).
    ///
    /// Data expected by this instruction:
    ///   `TransferInstructionData` or `TransferWithAuditorInstructionData` depending on whether
    ///   the transfer auditor feature is enabled for the SPL Token mint
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
    ///   None
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
    data.extend_from_slice(pod_bytes_of(instruction_data));
    Instruction {
        program_id: id(),
        accounts,
        data,
    }
}

fn _configure_mint(
    funding_address: Pubkey,
    token_mint_address: Pubkey,
    transfer_auditor_pk_and_freeze_authority: Option<(PodElGamalPK, Pubkey)>,
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

/// Create a `ConfidentialTokenInstruction::ConfigureMint` instruction
pub fn configure_mint(funding_address: Pubkey, token_mint_address: Pubkey) -> Instruction {
    _configure_mint(funding_address, token_mint_address, None)
}

/// Create a `ConfidentialTokenInstruction::ConfigureMint` instruction with a transfer auditor
pub fn configure_mint_with_transfer_auditor(
    funding_address: Pubkey,
    token_mint_address: Pubkey,
    transfer_auditor_pk: PodElGamalPK,
    freeze_authority: Pubkey,
) -> Instruction {
    _configure_mint(
        funding_address,
        token_mint_address,
        Some((transfer_auditor_pk, freeze_authority)),
    )
}

/// Create a `ConfidentialTokenInstruction::UpdateAccountPk` instruction
pub fn update_account_pk(
    zk_token_account: Pubkey,
    token_account: Pubkey,
    owner: Pubkey,
    multisig_signers: &[&Pubkey],
    data: UpdateAccountPkData,
) -> Vec<Instruction> {
    let mut accounts = vec![
        AccountMeta::new(zk_token_account, false),
        AccountMeta::new_readonly(token_account, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(owner, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    vec![
        ProofInstruction::VerifyUpdateAccountPk.encode(&data),
        encode_instruction(accounts, ConfidentialTokenInstruction::UpdateAccountPk, &()),
    ]
}
