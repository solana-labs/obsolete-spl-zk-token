use merlin::Transcript;
use rand_core::OsRng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul};

use crate::encryption::elgamal::{ElGamalCT, ElGamalSK};
use crate::errors::ProofError;
use crate::transcript::TranscriptProtocol;

/// Close a confidential token account by transferring all lamports it holds to the destination
/// account. The account must not hold any confidential tokens in its pending or available
/// balances. Use `DisableInboundTransfers` to block inbound transfers first if necessary.
///
///   0. `[writable]` The CToken account to close
///   1. `[]` Corresponding SPL Token account
///   2. `[writable]` The destination account
///   3. `[signer]` The single account owner
/// or:
///   3. `[]` The multisig account owner
///   4.. `[signer]` Required M signer accounts for the SPL Token Multisig account
///
/// Implementing it here as a struct for demonstration
#[allow(dead_code)]
struct CloseAccount {
    /// Proof that the encrypted balance is 0
    proof_component: CloseAccountProofData, // 128 bytes
}

/// This struct includes the cryptographic proof *and* the account data information needed to verify
/// the proof
///
/// - The pre-instruction should call CloseAccountProofData::verify_proof(&self)
/// - The actual program should check that `source_available_balance` is consistent with what is
///   currently stored in the confidential token account
///
pub struct CloseAccountProofData {
    /// The source account available balance in encrypted form
    pub source_available_balance: ElGamalCT, // 64 bytes

    /// Proof that the source account available balance is zero
    pub proof: CloseAccountProof, // 64 bytes
}

impl CloseAccountProofData {
    /// Create CloseAccountProofData including the proof
    pub fn create(source_sk: &ElGamalSK, source_available_balance: &ElGamalCT) -> Self {
        // generate a new transcript
        //
        // we can alteratively define the function to take in a transcript as
        // input see https://merlin.cool/use/passing.html
        let mut transcript = Transcript::new(b"Solana CToken on testnet: CloseAccountData");

        // generate proof that the current balance is zero
        let proof = CloseAccountProof::create(source_sk, source_available_balance, &mut transcript);

        CloseAccountProofData {
            source_available_balance: *source_available_balance,
            proof,
        }
    }

    /// Verify CloseAccountProof
    pub fn verify_proof(&self) -> Result<(), ProofError> {
        let Self {
            source_available_balance,
            proof,
        } = self;

        let mut transcript = Transcript::new(b"Solana CToken on testnet: CloseAccountData");
        proof.verify(source_available_balance, &mut transcript)
    }
}

/// This struct represents the cryptographic proof component that certifies that the encrypted
/// spendable balance is zero
#[allow(non_snake_case)]
pub struct CloseAccountProof {
    pub R: CompressedRistretto, // 32 bytes
    pub z: Scalar,              // 32 bytes
}

#[allow(non_snake_case)]
impl CloseAccountProof {
    pub fn create(
        source_sk: &ElGamalSK,
        source_current_balance: &ElGamalCT,
        transcript: &mut Transcript,
    ) -> Self {
        // add a domain separator to record the start of the protocol
        transcript.close_account_proof_domain_sep();

        // extract the relevant scalar and Ristretto points from the input
        let s = source_sk.get_scalar();
        let C = source_current_balance.decrypt_handle.get_point();

        // generate a random masking factor that also serves as a nonce
        let r = Scalar::random(&mut OsRng); // using OsRng for now
        let R = (r * C).compress();

        // record R on transcript and receive a challenge scalar
        transcript.append_point(b"R", &R);
        let c = transcript.challenge_scalar(b"c");

        // compute the masked secret key
        let z = c * s + r;

        CloseAccountProof { R, z }
    }

    pub fn verify(
        &self,
        source_current_balance: &ElGamalCT,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        // add a domain separator to record the start of the protocol
        transcript.close_account_proof_domain_sep();

        // extract the relevant scalar and Ristretto points from the input
        let C = source_current_balance.message_comm.get_point();
        let D = source_current_balance.decrypt_handle.get_point();

        let R = self.R;
        let z = self.z;

        // generate a challenge scalar
        transcript.validate_and_append_point(b"R", &R)?;
        let c = transcript.challenge_scalar(b"c");

        // decompress R or return verification error
        let R = R.decompress().ok_or(ProofError::VerificationError)?;

        // check the required algebraic relation
        let check = RistrettoPoint::multiscalar_mul(vec![z, -c, -Scalar::one()], vec![D, C, R]);

        if check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::encryption::elgamal::ElGamal;

    #[test]
    fn test_close_account_correctness() {
        let (source_pk, source_sk) = ElGamal::keygen();

        // If account balance is 0, then the proof should succeed
        let source_current_balance = source_pk.encrypt(0 as u64);

        let mut transcript_prove = Transcript::new(b"CloseAccountProof Test");
        let mut transcript_verify = Transcript::new(b"CloseAccountProof Test");

        let proof =
            CloseAccountProof::create(&source_sk, &source_current_balance, &mut transcript_prove);
        assert!(proof
            .verify(&source_current_balance, &mut transcript_verify)
            .is_ok());

        // If account balance is not zero, then the proof verification should fail
        let source_current_balance = source_pk.encrypt(55 as u64);

        let mut transcript_prove = Transcript::new(b"CloseAccountProof Test");
        let mut transcript_verify = Transcript::new(b"CloseAccountProof Test");

        let proof =
            CloseAccountProof::create(&source_sk, &source_current_balance, &mut transcript_prove);
        assert!(proof
            .verify(&source_current_balance, &mut transcript_verify)
            .is_err());
    }
}
