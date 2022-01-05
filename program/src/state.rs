use {
    crate::pod::*,
    bytemuck::{Pod, Zeroable},
    solana_program::pubkey::Pubkey,
    solana_zk_token_sdk::zk_token_elgamal::pod,
};
#[cfg(not(target_arch = "bpf"))]
use {solana_zk_token_sdk::encryption::auth_encryption::AeKey, std::convert::TryInto};

/// Mint data
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ZkMint {
    /// The corresponding SPL Token Mint
    pub mint: Pubkey,

    /// Optional auditor
    pub auditor: Auditor,
}
impl PodAccountInfo<'_, '_> for ZkMint {}

/// Auditing configuration
#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(C)]
pub struct Auditor {
    /// * If not Pubkey::default(), this authority must be provided to the `EnableBalanceCredits`
    /// instruction and effectively provides central control over who may enable the corresponding
    /// confidential token.
    ///
    /// * If Pubkey::default(), the token account owner must be provided to the
    /// `EnableBalanceCredits` instruction. In this configuration a confidential token is available
    /// for unrestricted public use.
    pub enable_balance_credits_authority: Pubkey,

    /// * If non-zero, transfers must include ElGamal cypertext with this public key.
    /// * If all zero, transfer auditing is disabled.  Once disabled, auditing may not be
    /// re-enabled.
    pub auditor_pk: pod::ElGamalPubkey,
}

impl Auditor {
    pub fn maybe_enable_balance_credits_authority(&self) -> Option<&Pubkey> {
        if self.enable_balance_credits_authority != Pubkey::default() {
            Some(&self.enable_balance_credits_authority)
        } else {
            None
        }
    }

    pub fn auditor_enabled(&self) -> bool {
        self.auditor_pk != pod::ElGamalPubkey::zeroed()
    }
}

/// Account data
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ZkAccount {
    /// The corresponding SPL Token Mint
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
    pub decryptable_available_balance: pod::AeCiphertext,

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
impl PodAccountInfo<'_, '_> for ZkAccount {}

impl ZkAccount {
    pub fn allow_balance_credits(&self) -> bool {
        bool::from(&self.allow_balance_credits)
    }

    pub fn pending_balance_credits(&self) -> u64 {
        u64::from(self.pending_balance_credit_counter)
            .saturating_sub(self.actual_pending_balance_credit_counter.into())
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn decryptable_available_balance(&self, aes_key: &AeKey) -> Option<u64> {
        let decryptable_available_balance = self.decryptable_available_balance.try_into().ok()?;
        aes_key.decrypt(&decryptable_available_balance)
    }
}
