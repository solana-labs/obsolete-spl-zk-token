//! Program instructions

use {
    crate::*,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{
        //instruction::{AccountMeta, Instruction},
        msg,
        program_error::ProgramError,
        program_pack::{Pack, Sealed},
        //pubkey::Pubkey,
        //sysvar,
    },
};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub enum TransferProof {
    CiphertextValidity(TransDataCTValidity),
    Range(TransDataRangeProof),
}

/// Instructions supported by the Feature Proposal program
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
pub enum ConfidentialTokenInstruction {
    /// Configures confidential transfers for a given SPL Token mint
    ///
    /// This instruction:
    /// * Creates the omnibus account that will be used to store all SPL Tokens deposited into the
    ///   confidential accounts this mint.
    /// * Creates the TransferAuditor account.
    ///
    /// If the SPL Token has a freeze authority configured, the freeze authority must be a signer
    /// and a transfer auditor may be optionally configured.
    /// Otherwise this instruction requires no signers, and a transfer auditor is cannot be
    /// configured.
    ///
    /// The instruction fails if the confidential transfers are already configured for the mint.
    ///
    /// Accounts expected by this instruction:
    ///   0. `[writeable,signer]` Funding account (must be a system account)
    ///   1. `[]` The SPL Token mint account to enable confidential transfers on
    ///   2. `[writable]` The omnibus SPL Token account to create, computed by `get_omnibus_token_address()`
    ///   3. `[writable]` The TransferAuditor account to create, computed by `get_transfer_auditor_address()`
    ///   4. `[]` System program
    ///   5. `[]` SPL Token program
    ///   6. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   7. `[signer]` (optional) The SPL Token mint freeze authority, if not `None`
    ///
    /// TODO: allow signer to be multisig
    ///
    Configure {
        /// `transfer_auditor` must be `None` if the SPL Token mint has no freeze authority
        #[allow(dead_code)] // not dead code
        transfer_auditor_pk: Option<ElGamalPK>,
    },

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
    UpdateTransferAuditor {
        /// The new `transfer_auditor` public key. Use `None` to disable the transfer auditor
        /// feature.
        #[allow(dead_code)] // not dead code
        new_transfer_auditor_pk: Option<ElGamalPK>,
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
    ///   0. `[writeable,signer]` Funding account (must be a system account)
    ///   1. `[writable]` The new confidential token account to create, as computed by `get_confidential_token_address()`
    ///   2. `[]` Corresponding SPL Token account
    ///   3. `[]` System program
    ///   5. `[]` Rent sysvar (remove once https://github.com/solana-labs/solana-program-library/pull/2282 is deployed)
    ///   6. `[signer]` The single source account owner
    /// or:
    ///   6. `[]` The multisig source account owner
    ///   7.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    CreateAccount {
        /// The public key associated with the account
        #[allow(dead_code)] // not dead code
        elgaml_pk: ElGamalPK,
    },

    /// Close a confidential token account by transferring all its SOL to the destination account.
    /// The account must not hold any confidential tokens in its pending or available balances.
    /// Use `DisableInboundTransfers` to block inbound transfers first if necessary.
    ///
    ///   0. `[writable]` The CToken account to close
    ///   1. `[]` Corresponding SPL Token account
    ///   2. `[writable]` The destination account
    ///   3. `[signer]` The single account close authority or owner
    /// or:
    ///   3. `[]` The multisig account close authority or owner
    ///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    CloseAccount {
        /// TODO: Proof that the encrypted balance is 0
        #[allow(dead_code)] // not dead code
        crypto_empty_balance_proof: bool,
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
    ///   2. `[signer]` The single account owner
    /// or:
    ///   2. `[]` The multisig account owner
    ///   3.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    UpdateAccountPk {
        #[allow(dead_code)] // not dead code
        elgaml_pk: ElGamalPK,
        #[allow(dead_code)] // not dead code
        pending_balance: ElGamalCT,
        #[allow(dead_code)] // not dead code
        available_balance: ElGamalCT,

        #[allow(dead_code)] // not dead code
        new_elgaml_pk: ElGamalPK,
        #[allow(dead_code)] // not dead code
        new_pending_balance: ElGamalCT,
        #[allow(dead_code)] // not dead code
        new_available_balance: ElGamalCT,

        /// TODO: Proof that the encrypted balances are equivalent
        #[allow(dead_code)] // not dead code
        crypto_balance_equality_proof: bool,
    },

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
    Deposit {
        /// The amount of tokens to deposit.
        #[allow(dead_code)] // not dead code
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        #[allow(dead_code)] // not dead code
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
    ///   6. `[signer]` The single source account owner
    /// or:
    ///   6. `[]` The multisig  source account owner
    ///   7.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    Withdraw {
        /// The amount of tokens to withdraw.
        #[allow(dead_code)] // not dead code
        amount: u64,
        /// Expected number of base 10 digits to the right of the decimal place.
        #[allow(dead_code)] // not dead code
        decimals: u8,
        /// TODO: Proof that the encrypted balance is >= `amount`
        #[allow(dead_code)] // not dead code
        crypto_sufficient_balance_proof: bool,
    },

    /// Submits a transfer proof. The two proof submissions required before the `Transfer`
    /// instruction will succeed are:
    /// * `TransferProof::CiphertextValidity`
    /// * `TransferProof::Range`
    ///
    ///   0. `[writable]` The source confidential token account
    ///   1. `[]` The source's corresponding SPL Token account
    ///   2. `[]` The destination confidential token account
    ///   3. `[signer]` The single source account owner
    /// or:
    ///   3. `[]` The multisig  source account owner
    ///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
    ///
    SubmitTransferProof {
        /// The receiver's ElGamal public key
        #[allow(dead_code)] // not dead code
        receiver_pk: ElGamalPK,

        /// The receiver's pending balance, encrypted with `receiver_pk`
        #[allow(dead_code)] // not dead code
        receiver_pending_balance: ElGamalCT,

        #[allow(dead_code)] // not dead code
        transfer_proof: TransferProof,
    },

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
    ///   4. `[]` The TransferAuditor account, computed by `get_transfer_auditor_address()`
    ///
    /// The primary purpose of this instruction is to enable receiver and auditor visibility into a
    /// successful transfer and its balance, which can be determined by inspecting the `Transfer`
    /// instruction data and the status of the encompassing transaction (that is, access to
    /// on-chain account data is not required).
    ///
    Transfer {
        /// Receiver's encryption key
        #[allow(dead_code)] // not dead code
        receiver_pk: ElGamalPK,

        /// Transfer amount split into two 32 values and encrypted so only the receiver can view it
        ///
        /// TODO: This tuple should be two 32 values instead of two 64 byte values
        #[allow(dead_code)] // not dead code
        receiver_transfer_split_amount: (ElGamalCT, ElGamalCT),

        /// Transfer auditor's encryption key
        #[allow(dead_code)] // not dead code
        transfer_auditor_pk: Option<ElGamalPK>,

        /// Transfer amount encrypted and split into two 32 values so only the optional transfer auditor can view it
        ///
        /// TODO: This tuple should be two 32 values instead of two 64 byte values
        #[allow(dead_code)] // not dead code
        transfer_auditor_split_amount: Option<(ElGamalCT, ElGamalCT)>,

        /// TODO: Proof that `transfer_auditor_split_amount` is equal to `receiver_transfer_split_amount`
        #[allow(dead_code)] // not dead code
        crypto_auditor_amount_equality_proof: bool,
    },

    /// Applies the pending balance to the available balance then clears the pending balance from a
    /// confidential token account.
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
    EnableInboundTransfers,
}

impl Sealed for ConfidentialTokenInstruction {}
impl Pack for ConfidentialTokenInstruction {
    const LEN: usize = 324; // see `test_get_packed_len()`

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
