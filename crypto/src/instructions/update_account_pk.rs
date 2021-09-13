#[cfg(not(target_arch = "bpf"))]
use {crate::encryption::elgamal::ElGamalSK, rand::rngs::OsRng};
use {
    crate::{
        encryption::{
            elgamal::{ElGamalCT, ElGamalPK, PodElGamalCT, PodElGamalPK},
            pedersen::PedersenBase,
        },
        errors::ProofError,
        pod_curve25519_dalek::*,
        transcript::TranscriptProtocol,
    },
    curve25519_dalek::{
        ristretto::RistrettoPoint,
        scalar::Scalar,
        traits::{IsIdentity, MultiscalarMul},
    },
    merlin::Transcript,
    std::convert::TryInto,
    zeroable::Zeroable,
};

/// Update the confidential token account's ElGamal public key.
///
/// This instruction will fail the pending balance is not empty, so invoking
/// `ApplyPendingBalance` first is recommended.
///
/// If the account is heavily used, consider invoking `DisableInboundTransfers` in a separate
/// transaction first to avoid new inbound transfers from causing this instruction to fail.
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
/// Implementing it here as a struct for demonstration
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UpdateAccountPK {
    /// New ElGamal encryption key
    new_pk: PodElGamalPK, // 32 bytes
    /// New encrypted available balance
    new_ct: PodElGamalCT, // 64 bytes
    /// Proof that the encrypted balances are equivalent
    proof_component: UpdateAccountPKProofData, // 224 bytes
}

/// This struct includes the cryptographic proof *and* the account data information needed to verify
/// the proof
///
/// - The pre-instruction should call UpdateAccountPKProofData::verify_proof(&self, &new_ct)
/// - The actual program should check that `current_ct` is consistent with what is
///   currently stored in the confidential token account
///
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct UpdateAccountPKProofData {
    /// Current source available balance encrypted under `current_pk`
    pub current_ct: PodElGamalCT, // 64 bytes

    /// Proof that the current and new ciphertexts are consistent
    pub proof: UpdateAccountPKProof, // 160 bytes
}

impl UpdateAccountPKProofData {
    /// Create UpdateAccountPublicKeyData including the proof
    #[cfg(not(target_arch = "bpf"))]
    pub fn create(
        current_balance: u64,
        current_sk: &ElGamalSK,
        new_pk: &ElGamalPK,
        new_sk: &ElGamalSK,
        current_ct: &ElGamalCT,
    ) -> Self {
        // generate a new transcript
        let mut transcript =
            Transcript::new(b"Solana CToke on testnet: UpdateAccountPublicKeyData");

        // encrypt current_balance under the new public key
        let new_ct = new_pk.encrypt(current_balance);

        // generate consistency proof
        let proof = UpdateAccountPKProof::create(
            current_balance,
            current_sk,
            new_sk,
            current_ct,
            &new_ct,
            &mut transcript,
        );

        UpdateAccountPKProofData {
            current_ct: (*current_ct).into(),
            proof,
        }
    }

    /// Verify UpdateAccountPublicKeyProof
    pub fn verify_proof(&self, new_ct: &ElGamalCT) -> Result<(), ProofError> {
        let current_ct: ElGamalCT = self.current_ct.try_into()?;
        let mut transcript =
            Transcript::new(b"Solana CToken on testnet: UpdateAccountPublicKeyData");
        self.proof.verify(&current_ct, new_ct, &mut transcript)
    }
}

/// This struct represents the cryptographic proof component that certifies that the current_ct and
/// new_ct encrypt equal values
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct UpdateAccountPKProof {
    pub R_0: PodCompressedRistretto, // 32 bytes
    pub R_1: PodCompressedRistretto, // 32 bytes
    pub z_sk_0: PodScalar,           // 32 bytes
    pub z_sk_1: PodScalar,           // 32 bytes
    pub z_x: PodScalar,              // 32 bytes
}

#[allow(non_snake_case)]
impl UpdateAccountPKProof {
    #[cfg(not(target_arch = "bpf"))]
    pub fn create(
        current_balance: u64,
        current_sk: &ElGamalSK,
        new_sk: &ElGamalSK,
        current_ct: &ElGamalCT,
        new_ct: &ElGamalCT,
        transcript: &mut Transcript,
    ) -> Self {
        // add a domain separator to record the start of the protocol
        transcript.update_account_public_key_proof_domain_sep();

        // extract the relevant scalar and Ristretto points from the input
        let s_0 = current_sk.get_scalar();
        let s_1 = new_sk.get_scalar();
        let x = Scalar::from(current_balance);

        let D_0 = current_ct.decrypt_handle.get_point();
        let D_1 = new_ct.decrypt_handle.get_point();

        let G = PedersenBase::default().G;

        // generate a random masking factor that also serves as a nonce
        let r_sk_0 = Scalar::random(&mut OsRng);
        let r_sk_1 = Scalar::random(&mut OsRng);
        let r_x = Scalar::random(&mut OsRng);

        let R_0 = (r_sk_0 * D_0 + r_x * G).compress();
        let R_1 = (r_sk_1 * D_1 + r_x * G).compress();

        // record R_0, R_1 on transcript and receive a challenge scalar
        transcript.append_point(b"R_0", &R_0);
        transcript.append_point(b"R_1", &R_1);
        let c = transcript.challenge_scalar(b"c");
        let _w = transcript.challenge_scalar(b"w"); // for consistency of transcript

        // compute the masked secret keys and amount
        let z_sk_0 = c * s_0 + r_sk_0;
        let z_sk_1 = c * s_1 + r_sk_1;
        let z_x = c * x + r_x;

        UpdateAccountPKProof {
            R_0: R_0.into(),
            R_1: R_1.into(),
            z_sk_0: z_sk_0.into(),
            z_sk_1: z_sk_1.into(),
            z_x: z_x.into(),
        }
    }

    pub fn verify(
        &self,
        current_ct: &ElGamalCT,
        new_ct: &ElGamalCT,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        // add a domain separator to record the start of the protocol
        transcript.update_account_public_key_proof_domain_sep();

        // extract the relevant scalar and Ristretto points from the input
        let C_0 = current_ct.message_comm.get_point();
        let D_0 = current_ct.decrypt_handle.get_point();

        let C_1 = new_ct.message_comm.get_point();
        let D_1 = new_ct.decrypt_handle.get_point();

        let R_0 = self.R_0.into();
        let R_1 = self.R_1.into();
        let z_sk_0 = self.z_sk_0.into();
        let z_sk_1: Scalar = self.z_sk_1.into();
        let z_x = self.z_x.into();

        let G = PedersenBase::default().G;

        // generate a challenge scalar
        transcript.validate_and_append_point(b"R_0", &R_0)?;
        transcript.validate_and_append_point(b"R_1", &R_1)?;
        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w");

        // decompress R_0, R_1 or return verification error
        let R_0 = R_0.decompress().ok_or(ProofError::VerificationError)?;
        let R_1 = R_1.decompress().ok_or(ProofError::VerificationError)?;

        // check the required algebraic relation
        let check = RistrettoPoint::multiscalar_mul(
            vec![
                z_sk_0,
                z_x,
                -c,
                -Scalar::one(),
                w * z_sk_1,
                w * z_x,
                -w * c,
                -w * Scalar::one(),
            ],
            vec![D_0, G, C_0, R_0, D_1, G, C_1, R_1],
        );

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
    fn test_update_account_public_key_correctness() {
        let (current_pk, current_sk) = ElGamal::keygen();
        let (new_pk, new_sk) = ElGamal::keygen();

        // If current_ct and new_ct encrypt same values, then the proof verification should succeed
        let balance: u64 = 77;
        let current_ct = current_pk.encrypt(balance);
        let new_ct = new_pk.encrypt(balance);

        let mut transcript_prove = Transcript::new(b"UpdateAccountPublicKeyProof Test");
        let mut transcript_verify = Transcript::new(b"UpdateAccountPublicKeyProof Test");

        let proof = UpdateAccountPKProof::create(
            balance,
            &current_sk,
            &new_sk,
            &current_ct,
            &new_ct,
            &mut transcript_prove,
        );
        assert!(proof
            .verify(&current_ct, &new_ct, &mut transcript_verify)
            .is_ok());

        // If current_ct and new_ct encrypt different values, then the proof verification should fail
        let new_ct = new_pk.encrypt(55_u64);

        let mut transcript_prove = Transcript::new(b"UpdateAccountPublicKeyProof Test");
        let mut transcript_verify = Transcript::new(b"UpdateAccountPublicKeyProof Test");

        let proof = UpdateAccountPKProof::create(
            balance,
            &current_sk,
            &new_sk,
            &current_ct,
            &new_ct,
            &mut transcript_prove,
        );
        assert!(proof
            .verify(&current_ct, &new_ct, &mut transcript_verify)
            .is_err());
    }
}
