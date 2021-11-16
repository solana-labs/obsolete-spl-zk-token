use {
    crate::pod::*,
    bytemuck::{Pod, Zeroable},
    solana_program::pubkey::Pubkey,
    spl_zk_token_sdk::zk_token_elgamal::pod,
};
#[cfg(not(target_arch = "bpf"))]
use {spl_zk_token_sdk::encryption::aes::AesKey, std::convert::TryInto};

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
    pub decryptable_available_balance: pod::AesCiphertext,

    /// `pending_balance` may only be credited by `Deposit` or `Transfer` instructions if `true`
    pub allow_balance_credits: PodBool,

    /// The total number of `Deposit` and `Transfer` instructions that have credited `pending_balance`
    pub pending_balance_credit_counter: PodU64,

    /// The `expected_pending_balance_credit_counter` value that was included in the last
    /// `ApplyPendingBalance` instruction
    pub expected_pending_balance_credit_counter: PodU64,

    /// The actual `pending_balance_credit_counter` when the last `ApplyPendingBalance` instruction was executed
    pub actual_pending_balance_credit_counter: PodU64,
}
impl PodAccountInfo<'_, '_> for ConfidentialAccount {}

impl ConfidentialAccount {
    pub fn allow_balance_credits(&self) -> bool {
        bool::from(&self.allow_balance_credits)
    }

    pub fn pending_balance_credits(&self) -> u64 {
        u64::from(self.pending_balance_credit_counter)
            .saturating_sub(self.actual_pending_balance_credit_counter.into())
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn decryptable_available_balance(&self, aes_key: &AesKey) -> Option<u64> {
        let decryptable_available_balance = self.decryptable_available_balance.try_into().ok()?;
        aes_key.decrypt(&decryptable_available_balance)
    }
}
