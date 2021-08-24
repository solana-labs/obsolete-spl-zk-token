use {
    crate::*,
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{
        msg,
        program_error::ProgramError,
        program_pack::{Pack, Sealed},
        pubkey::Pubkey,
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

impl Sealed for TransferAuditor {}
impl Pack for TransferAuditor {
    const LEN: usize = 65; // see `test_get_packed_len()`

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let data = self.try_to_vec().unwrap();
        dst[..data.len()].copy_from_slice(&data);
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let mut mut_src: &[u8] = src;
        Self::deserialize(&mut mut_src).map_err(|err| {
            msg!(
                "Error: failed to deserialize transfer auditor account: {}",
                err
            );
            ProgramError::InvalidAccountData
        })
    }
}

#[derive(Clone, Default, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct OutboundTransfer {
    /// `true` once a validity proof has been accepted for this transfer
    pub validity_proof: bool,

    /// `true` once a range proof has been accepted for this transfer
    pub range_proof: bool,

    /// Transfer amount encrypted by the sender's `ConfidentialAccount::elgaml_pk`
    pub sender_transfer_amount: ElGamalCT,

    /// The receiver's ElGamal public key
    pub receiver_pk: ElGamalPK,

    /// The receiver's pending balance encrypted with `receiver_pk`
    pub receiver_pending_balance: ElGamalCT,

    /// Transfer amount encrypted with `receiver_pk`
    pub receiver_transfer_amount: ElGamalCT,
}

/// State for a confidential token account
#[derive(Clone, Default, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct ConfidentialAccount {
    /// The SPL Token mint associated with this confidential token account
    pub mint: Pubkey,

    /// The SPL Token account that corresponds to this confidential token account.
    /// The owner and close authority of the SPL Token account convey their authority over the
    /// confidential token account
    pub token_account: Pubkey,

    /// The public key associated with ElGamal encryption
    pub elgaml_pk: ElGamalPK,

    /// The pending balance (encrypted by `elgaml_pk`)
    pub pending_balance: ElGamalCT,

    /// The available balance (encrypted by `elgaml_pk`)
    pub available_balance: ElGamalCT,

    /// Prohibit incoming transfers if `false`
    pub accept_incoming_transfers: bool,

    /// Contains the details of an outbound transfer if `Some`.
    /// Resets to `None` upon transfer completion or rejection of the outbound transfer.
    pub outbound_transfer: OutboundTransfer,
}

impl Sealed for ConfidentialAccount {}
impl Pack for ConfidentialAccount {
    const LEN: usize = 451; // see `test_get_packed_len()`

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let data = self.try_to_vec().unwrap();
        dst[..data.len()].copy_from_slice(&data);
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let mut mut_src: &[u8] = src;
        Self::deserialize(&mut mut_src).map_err(|err| {
            msg!("Error: failed to confidential token account: {}", err);
            ProgramError::InvalidAccountData
        })
    }
}

#[cfg(test)]
mod tests {
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

    /*
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
