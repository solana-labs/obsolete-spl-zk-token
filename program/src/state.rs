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
    /// The owner and close authority of the SPL Token account convey their authority over the
    /// confidential token account
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

    /// Counts the number of incoming transfers
    pub incoming_transfer_count: PodU64,

    /// Record of `incoming_transfer_count` at the time of the most recent `ApplyPendingBalance`
    pub applied_incoming_transfer_count: TransferCountRecord,
}
impl PodAccountInfo<'_, '_> for ConfidentialAccount {}

/// After submitting `ApplyPendingBalance`, the client should compare the expected and the actual
/// transfer counts. If they are equal, then the `decryptable_balance` is consistent with
/// `available_balance`. If they differ, then the client should update the `decryptable_balance`.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct TransferCountRecord {
    /// The expected `incoming_transfer_count` that was included in the `ApplyPendingBalance`
    /// instruction
    pub expected_incoming_transfer_count: PodU64,

    /// The actual `incoming_transfer_count` at the time the `ApplyPendingBalance` was executed
    pub actual_incoming_transfer_count: PodU64,
}

#[cfg(test)]
mod tests {
    /*
    use super::*;

    #[test]
    fn test_get_packed_len() {
        assert_eq!(
            Auditor::get_packed_len(),
            solana_program::borsh::get_packed_len::<Auditor>()
        );

        assert_eq!(
            ConfidentialAccount::get_packed_len(),
            solana_program::borsh::get_packed_len::<ConfidentialAccount>()
        );
    }

    #[test]
    fn test_serialize_bytes() {
        assert_eq!(FeatureProposal::Expired.try_to_vec().unwrap(), vec![3]);

        assert_eq!(
            FeatureProposal::Pending(AcceptanceCriteria {
                tokens_required: 0xdeadbeefdeadbeef,
                deadline: -1,
            })
            .try_to_vec()
            .unwrap(),
            vec![1, 239, 190, 173, 222, 239, 190, 173, 222, 255, 255, 255, 255, 255, 255, 255, 255],
        );
    }

    #[test]
    fn test_serialize_large_slice() {
        let mut dst = vec![0xff; 4];
        FeatureProposal::Expired.pack_into_slice(&mut dst);

        // Extra bytes (0xff) ignored
        assert_eq!(dst, vec![3, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn state_deserialize_invalid() {
        assert_eq!(
            FeatureProposal::unpack_from_slice(&[3]),
            Ok(FeatureProposal::Expired),
        );

        // Extra bytes (0xff) ignored...
        assert_eq!(
            FeatureProposal::unpack_from_slice(&[3, 0xff, 0xff, 0xff]),
            Ok(FeatureProposal::Expired),
        );

        assert_eq!(
            FeatureProposal::unpack_from_slice(&[4]),
            Err(ProgramError::InvalidAccountData),
        );
    }
    */
}
