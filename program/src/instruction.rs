//! Program instructions

use {
    crate::*,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{
        instruction::{AccountMeta, Instruction},
        msg,
        program_error::ProgramError,
        program_pack::{Pack, Sealed},
        pubkey::Pubkey,
        sysvar,
    },
};

/// Account used for auditing confidential transfers
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub struct TransferAuditor {
    /// The SPL Token mint associated with this account
    pub mint: Pubkey,

    /// ElGamal public key for the transfer auditor.
    ///
    /// If Some, transfers must include ElGamal cypertext using this public key.
    /// If None, transfer auditing is disabled
    pub transfer_auditor_pk: Option<ElGamalPK>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub enum TransferProof {
    CiphertextValidity(TransDataCTValidity),
    Range(TransDataRangeProof),
}

/// Instructions supported by the Feature Proposal program
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub enum ConfidentialTokenInstruction {
    /// Enables confidential transfers for a given SPL Token mint
    ///
    /// This instruction:
    /// * Creates the omnibus account that will be used to store all SPL Tokens deposited into the
    ///   confidential accounts this mint
    /// * Creates the TransferAuditor account
    ///
    /// If the SPL Token has a freeze authority configured, the freeze authority must be a signer
    /// and a transfer auditor may be optionally configured.
    /// Otherwise this instruction requires no signers, and a transfer auditor is cannot be
    /// configured.
    ///
    /// The instruction fails if the confidential transfers are already enabled.
    ///
    /// Accounts expected by this instruction:
    ///   0. `[]` The SPL Token mint account to enable confidential transfers on
    ///   1. `[writable]` The omnibus SPL Token account to create, computed by `get_omnibus_token_address()`
    ///   2. `[writable]` The TransferAuditor account to create, computed by `get_transfer_auditor_address()`
    ///   3. `[]` System program
    ///   4. `[]` SPL Token program
    ///   5. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   6. `[signer]` The SPL Token mint freeze authority (if not `None`).
    ///
    /// TODO: allow signer to be multisig
    ///
    EnableConfidentialTransfers {
        /// `transfer_auditor` must be `None` if the SPL Token mint has no freeze authority
        transfer_auditor: Option<ElGamalPK>,
    },

    /// Updates the transfer auditor ElGamal public key.
    /// This instruction fails if a transfer auditor is currently `None` for this Token mint.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The TransferAuditor account, computed by `get_transfer_auditor_address()`
    ///   1. `[]` The SPL Token mint account
    ///   1. `[signer]` The SPL Token mint freeze authority.
    ///
    /// TODO: allow signer to be multisig
    ///
    UpdateTransferAuditor {
        /// The new `transfer_auditor` public key. Use `None` to disable the transfer auditor
        /// feature.
        new_transfer_auditor: Option<ElGamalPK>,
    },

    /// Create a confidential token account
    ///
    /// this is a PDA, derived from the token mint and linked token account.  Ownership resides in
    /// the linked token account. This instruction fails if the confidential token account already
    /// exists.
    ///
    /// The instruction fails if the confidential token account already exists
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The new confidential token account to create, as computed by `get_confidential_token_address()`
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[]` System program
    ///   3. `[]` SPL Token program
    ///   4. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   5. `[signer]` The source account's owner
    ///
    /// TODO: allow the signer to be multisig
    ///
    CreateAccount {
        /// The public key associated with the account
        elgaml_pk: ElGamalPK,
    },

    /// Close a confidential token account by transferring all its SOL to the destination account.
    /// The account must not hold any confidential tokens in its pending or available balances.
    /// Use `DisableInboundTransfers` to block inbound transfers first if necessary.
    ///
    ///   0. `[writable]` The CToken account to close
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[writable]` The destination account
    ///   3. `[signer]` The account's close authority or owner
    ///
    /// TODO: allow the signer to be multisig
    ///
    CloseAccount {
        /// TODO: Crypto thing that proves the encrypted balance is 0
        crypto_thing: bool,
    },

    /// Updates the confidential token account's ElGamal public key. This instruction will fail the
    /// pending balance is not empty.
    ///
    /// As such in a separate transaction it's suggested to execute the `DisableInboundTransfers`
    /// and `ApplyPendingBalance` instructions first.  Once `UpdatePublicKey` is successfully,
    /// execute `EnableInboundTransfers` to re-enable inbouard transfers (which could be in the
    /// same transaction as `UpdatePublicKey`)
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account to update
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[signer]` The account owner
    ///
    /// TODO: allow the signer to be multisig
    ///
    UpdateAccountPublicKey(UpdateEncKeyData),

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
    ///   6. `[signer]` The source account's owner/delegate.
    ///
    /// TODO: allow the signer to be multisig
    ///
    Deposit {
        /// The amount of tokens to deposit.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
    },

    /// Withdraw SPL Tokens from the available balance of a confidential token account.
    ///
    /// Fails if the source or destination accounts are frozen, and will implicitly cancel a
    /// pending outbound transfer from the source account if present.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL token account
    ///   2. `[writable]` The destination SPL Token account
    ///   3. `[]` The token mint.
    ///   4. `[writable]` The omnibus SPL Token account for this token mint, computed by `get_omnibus_token_address()`
    ///   5. `[]` SPL Token program
    ///   6. `[signer]` The source account's owner
    ///
    /// TODO: allow the signer to be multisig
    ///
    Withdraw {
        /// The amount of tokens to withdraw.
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        decimals: u8,
        /// TODO: Crypto thing that proves the encrypted balance is >= `amount`
        crypto_thing: bool,
    },

    /// Submits a transfer proof. The two proof submissions required before the `Transfer`
    /// instruction will succeed are:
    /// * `TransferProof::CiphertextValidity`
    /// * `TransferProof::Range`
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL Token account
    ///   2. `[]` The destination confidential token account
    ///   3. `[signer]` The source account's owner
    ///
    /// TODO: allow the signer to be multisig
    ///
    SubmitTransferProof(TransferProof),

    /// Transfers tokens confidentially from one account to another. The prerequisite transfer
    /// proofs must have already been successfully submitted using `SubmitTransferProof` for this
    /// instruction to succeed.
    ///
    /// A transfer will fail if:
    /// * Either the source or the destination is frozen by the Token Mint's freeze authority
    /// * The destination has disabled incoming transfers by invoking `DisableInboundTransfers`
    /// * The destination received a transfer from another source that invalidates the previously
    ///   submitted transfer proofs
    /// * All prerequisite `TransferProof`s have not been submitted
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL Token account
    ///   2. `[writable]` The destination confidential token account
    ///   3. `[]` The destination token account
    ///   4. `[]` The SPL Token mint account
    ///   5. `[]` The TransferAuditor account, computed by `get_transfer_auditor_address()`
    ///
    /// The primary purpose of this instruction is to enable receiver and auditor visibility into a
    /// successful transfer and its balance, which can be determined by inspecting the `Transfer`
    /// instruction data and the status of the encompassing transaction (that is, access to
    /// on-chain account data is not required).
    ///
    Transfer {
        /// Receiver's encryption key
        receiver_pk: ElGamalPK,

        /// Transfer amount encrypted so only the receiver can view it
        ///
        /// TODO: This tuple should be two 32 values instead of two 64 byte values
        transfer_amount_ct_receiver: (ElGamalCT, ElGamalCT),

        /// Transfer auditor's encryption key
        transfer_auditor_pk: Option<ElGamalPK>,

        /// Transfer amount encrypted so only the optional transfer auditor can view it
        ///
        /// TODO: This tuple should be two 32 values instead of two 64 byte values
        transfer_amount_ct_auditor: Option<(ElGamalCT, ElGamalCT)>,

        /// TODO: Is there another crypto thing needed here to prove `transfer_amount_ct_auditor` field is correct?
        ///       Perhaps an equality proof that `transfer_amount_ct_auditor` is the same as
        ///       `transfer_amount_ct_receiver`?
        ///
        /// Note that:
        /// * `receiver_pk` and `transfer_amount_ct_receiver` will be validated in the program by comparing against
        ///    the contents of the `OutboundTransfer` struct in the source CToken account
        /// * `transfer_auditor_pk` will be validated in the program by comparing against the
        ///   `TransferAuditor::transfer_auditor_pk` field
        ///
        crypto_thing: bool,
    },

    /// Applies the pending balance to the available balance then clears the pending balance from a
    /// confidential token account.
    ///
    /// Account expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account.
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[signer]` The account owner.
    ///
    /// TODO: allow the signer to be multisig
    ///
    ApplyPendingBalance,

    /// Disable incoming transfers to a confidential token account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account.
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[signer]` The account owner.
    ///
    /// TODO: allow the signer to be multisig
    ///
    DisableInboundTransfers,

    /// Enable incoming transfers for a confidential token account.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The confidential token account.
    ///   1. `[]` The corresponding SPL Token account
    ///   2. `[signer]` The account owner.
    ///
    /// TODO: allow the signer to be multisig
    ///
    EnableInboundTransfers,
}

impl Sealed for ConfidentialTokenInstruction {}
impl Pack for ConfidentialTokenInstruction {
    const LEN: usize = 11; // see `test_get_packed_len()` for justification of this value

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let data = self.pack_into_vec();
        dst[..data.len()].copy_from_slice(&data);
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let mut mut_src: &[u8] = src;
        Self::deserialize(&mut mut_src).map_err(|err| {
            msg!("Error: failed to deserialize instruction: {}", err);
            ProgramError::InvalidInstructionData
        })
    }
}

impl ConfidentialTokenInstruction {
    fn pack_into_vec(&self) -> Vec<u8> {
        self.try_to_vec().expect("try_to_vec")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_packed_len() {
        assert_eq!(
            ConfidentialTokenInstruction::get_packed_len(),
            solana_program::borsh::get_packed_len::<ConfidentialTokenInstruction>()
        )
    }
}
