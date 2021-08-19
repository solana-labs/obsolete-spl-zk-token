use {
    crate::*,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{
        account_info::AccountInfo,
        entrypoint,
        entrypoint::ProgramResult,
        msg,
        pubkey::Pubkey,
        sysvar::{rent::Rent, Sysvar},
    },
};

/// Account used for auditing confidential transfers
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct TransferAuditor {
    /// The SPL Token mint associated with this account
    pub mint: Pubkey,

    /// ElGamal public key for the transfer auditor.
    ///
    /// If Some, transfers must include ElGamal cypertext using this public key.
    /// If None, transfer auditing is disabled
    pub transfer_auditor_pk: Option<ElGamalPK>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct OutboundTransfer {
    /// `true` once a validity proof has been accepted for this transfer
    pub validity_proof: bool,

    /// `true` once a range proof has been accepted for this transfer
    pub range_proof: bool,

    /// The receiver's ElGamal public key
    pub receiver_elgmal_pk: ElGamalPK,

    /// The receiver's pending balance, encrypted with `receiver_elgmal_pk`
    pub receiver_pending_balance: ElGamalCT,
}

/// State for a confidential token account
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct ConfidentialTokenAccount {
    /// The SPL Token mint associated with this confidential token account
    pub mint: Pubkey,

    /// The SPL Token account that corresponds to this confidential token account.
    /// The owner and close authority of the SPL Token account convey their authority over the
    /// confidential token account
    pub token_account: Pubkey,

    /// The public key associated with El Gamal encryption
    pub elgaml_pk: ElGamalPK, // 32 bytes

    /// The pending balance (encrypted by `elgaml_pk`)
    pub pending_balance: ElGamalCT, // 64 bytes

    /// The available balance (encrypted by `elgaml_pk`)
    pub available_balance: ElGamalCT, // 64 bytes

    /// Prohibit incoming transfers if `false`
    pub accept_incoming_transfers: bool,

    /// Contains the details of an outbound transfer if `Some`.
    /// Resets to `None` upon transfer completion or rejection of the outbound transfer.
    pub outbound_transfer: Option<OutboundTransfer>,
}
