use {crate::pod::*, spl_zk_token_crypto::pod::*, zeroable::Zeroable};

/// Account used for auditing confidential transfers
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferAuditor {
    /// The SPL Token mint associated with this account
    pub mint: PodPubkey,

    /// If true, transfers must include ElGamal cypertext using this public key.
    /// If false, transfer auditing is disabled
    pub enabled: PodBool,

    /// ElGamal public key for the transfer auditor.
    pub elgaml_pk: PodElGamalPK,
}
impl PodAccountInfo<'_, '_> for TransferAuditor {}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct OutboundTransfer {
    /// `true` once a validity proof has been accepted for this transfer
    pub validity_proof: PodBool,

    /// `true` once a range proof has been accepted for this transfer
    pub range_proof: PodBool,

    /// Transfer amount encrypted by the sender's `ConfidentialAccount::elgaml_pk`
    pub sender_transfer_amount: PodElGamalCT,

    /// The receiver's ElGamal public key
    pub receiver_pk: PodElGamalPK,

    /// The receiver's pending balance encrypted with `receiver_pk`
    pub receiver_pending_balance: PodElGamalCT,

    /// Transfer amount encrypted with `receiver_pk`
    pub receiver_transfer_amount: PodElGamalCT,
}
impl PodAccountInfo<'_, '_> for OutboundTransfer {}

/// State for a confidential token account
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ConfidentialAccount {
    /// The SPL Token mint associated with this confidential token account
    pub mint: PodPubkey,

    /// The SPL Token account that corresponds to this confidential token account.
    /// The owner and close authority of the SPL Token account convey their authority over the
    /// confidential token account
    pub token_account: PodPubkey,

    /// The public key associated with ElGamal encryption
    pub elgaml_pk: PodElGamalPK,

    /// The pending balance (encrypted by `elgaml_pk`)
    pub pending_balance: PodElGamalCT,

    /// The available balance (encrypted by `elgaml_pk`)
    pub available_balance: PodElGamalCT,

    /// Prohibit incoming transfers if `false`
    pub accept_incoming_transfers: PodBool,

    /// Contains the details of an outbound transfer if `Some`.
    /// Resets to `None` upon transfer completion or rejection of the outbound transfer.
    pub outbound_transfer: OutboundTransfer,
}
impl PodAccountInfo<'_, '_> for ConfidentialAccount {}

#[cfg(test)]
mod tests {
    /*
    use super::*;

    #[test]
    fn test_get_packed_len() {
        assert_eq!(
            TransferAuditor::get_packed_len(),
            solana_program::borsh::get_packed_len::<TransferAuditor>()
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
