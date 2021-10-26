use {
    crate::pod::*,
    bytemuck::{Pod, Zeroable},
    solana_program::pubkey::Pubkey,
    spl_zk_token_sdk::zk_token_elgamal::pod,
};

/// Account used for auditing confidential transfers
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Auditor {
    /// The SPL Token mint associated with this account
    pub mint: Pubkey,

    /// If true, transfers must include ElGamal cypertext using this public key.
    /// If false, transfer auditing is disabled
    pub enabled: PodBool,

    /// ElGamal public key for the auditor.
    pub elgamal_pk: pod::ElGamalPubkey,
}
impl PodAccountInfo<'_, '_> for Auditor {}

/// State for a confidential token account
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ConfidentialAccount {
    /// The SPL Token mint associated with this confidential token account
    pub mint: Pubkey,

    /// The SPL Token account that corresponds to this confidential token account.
    /// The owner of the SPL Token account convey their authority over the confidential token
    /// account
    pub token_account: Pubkey,

    /// The public key associated with ElGamal encryption
    pub elgamal_pk: pod::ElGamalPubkey,

    /// The pending balance (encrypted by `elgamal_pk`)
    pub pending_balance: pod::ElGamalCiphertext,

    /// The available balance (encrypted by `elgamal_pk`)
    pub available_balance: pod::ElGamalCiphertext,

    /// The decryptable available balance
    pub decryptable_balance: pod::AesCiphertext,

    /// Prohibit incoming transfers if `false`
    pub accept_incoming_transfers: PodBool,

    /// The total number of `Deposit` and `Transfer` instructions that have credited `pending_balance`
    pub pending_balance_instructions: PodU64,

    /// The expected `pending_balance_instructions` that was included in the last `ApplyPendingBalance`
    /// instruction
    pub expected_apply_pending_balance_instructions: PodU64,

    /// The actual `pending_balance_instructions` at last time the `ApplyPendingBalance` was executed
    pub actual_applied_pending_balance_instructions: PodU64,
}
impl PodAccountInfo<'_, '_> for ConfidentialAccount {}
