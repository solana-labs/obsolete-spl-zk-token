use {
    crate::pod::*,
    bytemuck::{Pod, Zeroable},
    spl_zk_token_crypto::pod::*,
    spl_zk_token_crypto::zk_token_proof_instruction::{
        TransferComms, TransferEphemeralState, TransferPubKeys,
    },
};

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
    pub elgamal_pk: PodElGamalPK,
}
impl PodAccountInfo<'_, '_> for TransferAuditor {}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct OutboundTransfer {
    /// `true` once a validity proof has been accepted for this transfer
    pub validity_proof: PodBool,

    /// `true` once a range proof has been accepted for this transfer
    pub range_proof: PodBool,

    /// The public encryption keys associated with the transfer: source, dest, and auditor
    pub transfer_public_keys: TransferPubKeys,

    /// The transfer amount encoded as Pedersen commitments
    pub amount_comms: TransferComms,

    /// The source and destination decryption handles
    pub source_lo: PodPedersenDecHandle,
    pub source_hi: PodPedersenDecHandle,
    pub dest_lo: PodPedersenDecHandle,
    pub dest_hi: PodPedersenDecHandle,

    /// The available balance in the source account after the transfer completes
    pub new_available_balance: PodElGamalCT,

    /// Ephemeral state between the two transfer instruction data
    pub ephemeral_state: TransferEphemeralState,
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
    pub elgamal_pk: PodElGamalPK,

    /// The pending balance (encrypted by `elgamal_pk`)
    pub pending_balance: PodElGamalCT,

    /// The available balance (encrypted by `elgamal_pk`)
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
