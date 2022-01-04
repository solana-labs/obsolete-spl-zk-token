#[cfg(not(target_arch = "bpf"))]
use {
    crate::encryption::{
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
        pedersen::{PedersenBase, PedersenCommitment, PedersenOpening},
    },
    curve25519_dalek::traits::MultiscalarMul,
    rand::rngs::OsRng,
};
use {
    crate::{sigma_proofs::errors::EqualityProofError, transcript::TranscriptProtocol},
    arrayref::{array_ref, array_refs},
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{IsIdentity, VartimeMultiscalarMul},
    },
    merlin::Transcript,
};

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct EqualityProof {
    pub Y_0: CompressedRistretto,
    pub Y_1: CompressedRistretto,
    pub Y_2: CompressedRistretto,
    pub z_s: Scalar,
    pub z_x: Scalar,
    pub z_r: Scalar,
}

#[allow(non_snake_case)]
#[cfg(not(target_arch = "bpf"))]
impl EqualityProof {
    pub fn new(
        elgamal_keypair: &ElGamalKeypair,
        ciphertext: &ElGamalCiphertext,
        message: u64,
        opening: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        // extract the relevant scalar and Ristretto points from the inputs
        let G = PedersenBase::default().G;
        let H = PedersenBase::default().H;

        let P_EG = elgamal_keypair.public.get_point();
        let D_EG = ciphertext.decrypt_handle.get_point();

        let s = elgamal_keypair.secret.get_scalar();
        let x = Scalar::from(message);
        let r = opening.get_scalar();

        // generate random masking factors that also serves as a nonce
        let y_s = Scalar::random(&mut OsRng);
        let y_x = Scalar::random(&mut OsRng);
        let y_r = Scalar::random(&mut OsRng);

        let Y_0 = (y_s * P_EG).compress();
        let Y_1 = RistrettoPoint::multiscalar_mul(vec![y_x, y_s], vec![G, D_EG]).compress();
        let Y_2 = RistrettoPoint::multiscalar_mul(vec![y_x, y_r], vec![G, H]).compress();

        // record masking factors in transcript
        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        transcript.append_point(b"Y_2", &Y_2);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // compute the masked values
        let z_s = c * s + y_s;
        let z_x = c * x + y_x;
        let z_r = c * r + y_r;

        EqualityProof {
            Y_0,
            Y_1,
            Y_2,
            z_s,
            z_x,
            z_r,
        }
    }

    pub fn verify(
        self,
        elgamal_pubkey: &ElGamalPubkey,
        ciphertext: &ElGamalCiphertext,
        commitment: &PedersenCommitment,
        transcript: &mut Transcript,
    ) -> Result<(), EqualityProofError> {
        // extract the relevant scalar and Ristretto points from the inputs
        let G = PedersenBase::default().G;
        let H = PedersenBase::default().H;

        let P_EG = elgamal_pubkey.get_point();
        let C_EG = ciphertext.message_comm.get_point();
        let D_EG = ciphertext.decrypt_handle.get_point();

        let C_Ped = commitment.get_point();

        // include Y_0, Y_1, Y_2 to transcript and extract challenges
        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w");
        let ww = w * w;

        // check that the required algebraic condition holds
        let Y_0 = self.Y_0.decompress().ok_or(EqualityProofError::Format)?;
        let Y_1 = self.Y_1.decompress().ok_or(EqualityProofError::Format)?;
        let Y_2 = self.Y_2.decompress().ok_or(EqualityProofError::Format)?;

        let check = RistrettoPoint::vartime_multiscalar_mul(
            vec![
                self.z_s,
                -c,
                -Scalar::one(),
                w * self.z_x,
                w * self.z_s,
                -w * c,
                -w,
                ww * self.z_x,
                ww * self.z_r,
                -ww * c,
                -ww,
            ],
            vec![P_EG, H, Y_0, G, D_EG, C_EG, Y_1, G, H, C_Ped, Y_2],
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(EqualityProofError::AlgebraicRelation)
        }
    }

    pub fn to_bytes(&self) -> [u8; 192] {
        let mut buf = [0_u8; 192];
        buf[..32].copy_from_slice(self.Y_0.as_bytes());
        buf[32..64].copy_from_slice(self.Y_1.as_bytes());
        buf[64..96].copy_from_slice(self.Y_2.as_bytes());
        buf[96..128].copy_from_slice(self.z_s.as_bytes());
        buf[128..160].copy_from_slice(self.z_x.as_bytes());
        buf[160..192].copy_from_slice(self.z_r.as_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EqualityProofError> {
        let bytes = array_ref![bytes, 0, 192];
        let (Y_0, Y_1, Y_2, z_s, z_x, z_r) = array_refs![bytes, 32, 32, 32, 32, 32, 32];

        let Y_0 = CompressedRistretto::from_slice(Y_0);
        let Y_1 = CompressedRistretto::from_slice(Y_1);
        let Y_2 = CompressedRistretto::from_slice(Y_2);

        let z_s = Scalar::from_canonical_bytes(*z_s).ok_or(EqualityProofError::Format)?;
        let z_x = Scalar::from_canonical_bytes(*z_x).ok_or(EqualityProofError::Format)?;
        let z_r = Scalar::from_canonical_bytes(*z_r).ok_or(EqualityProofError::Format)?;

        Ok(EqualityProof {
            Y_0,
            Y_1,
            Y_2,
            z_s,
            z_x,
            z_r,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::encryption::pedersen::Pedersen;

    #[test]
    fn test_equality_proof() {
        // success case
        let elgamal_keypair = ElGamalKeypair::default();
        let message: u64 = 55;

        let ciphertext = elgamal_keypair.public.encrypt(message);
        let (commitment, opening) = Pedersen::new(message);

        let mut transcript_prover = Transcript::new(b"Test");
        let mut transcript_verifier = Transcript::new(b"Test");

        let proof = EqualityProof::new(
            &elgamal_keypair,
            &ciphertext,
            message,
            &opening,
            &mut transcript_prover,
        );

        assert!(proof
            .verify(
                &elgamal_keypair.public,
                &ciphertext,
                &commitment,
                &mut transcript_verifier
            )
            .is_ok());

        // fail case: encrypted and committed messages are different
        let elgamal_keypair = ElGamalKeypair::default();
        let encrypted_message: u64 = 55;
        let committed_message: u64 = 77;

        let ciphertext = elgamal_keypair.public.encrypt(encrypted_message);
        let (commitment, opening) = Pedersen::new(committed_message);

        let mut transcript_prover = Transcript::new(b"Test");
        let mut transcript_verifier = Transcript::new(b"Test");

        let proof = EqualityProof::new(
            &elgamal_keypair,
            &ciphertext,
            message,
            &opening,
            &mut transcript_prover,
        );

        assert!(proof
            .verify(
                &elgamal_keypair.public,
                &ciphertext,
                &commitment,
                &mut transcript_verifier
            )
            .is_err());
    }
}
