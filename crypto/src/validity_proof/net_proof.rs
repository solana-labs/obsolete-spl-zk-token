use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;

use rand_core::{CryptoRng, RngCore};

use crate::elgamal::{ElGamalCT, ElGamalPK, ElGamalRand};
use crate::errors::ProofError;
use crate::transcript::TranscriptProtocol;

use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Deserialize, Serialize)]
pub struct NetZeroProof {
    // 160
    Y_0: CompressedRistretto, // 32
    Y_1: CompressedRistretto, // 32
    z_x: Scalar,              // 32
    z_0: Scalar,              // 32
    z_1: Scalar,              // 32
}

#[allow(non_snake_case)]
impl NetZeroProof {
    pub fn prove<T: RngCore + CryptoRng>(
        x: u64,
        eg_pk_0: &ElGamalPK,
        eg_pk_1: &ElGamalPK,
        eg_rand_0: &ElGamalRand,
        eg_rand_1: &ElGamalRand,
        transcript: &mut Transcript,
        rng: &mut T,
    ) -> NetZeroProof {
        transcript.net_zero_domain_sep();

        let H_0 = eg_pk_0.get_point();
        let H_1 = eg_pk_1.get_point();

        let x = Scalar::from(x);
        let r_0 = eg_rand_0.get_scalar();
        let r_1 = eg_rand_1.get_scalar();

        let y_x = Scalar::random(rng);
        let y_0 = Scalar::random(rng);
        let y_1 = Scalar::random(rng);

        let Y_0 = (y_x * G + y_0 * H_0).compress();
        let Y_1 = (y_x * G + y_1 * H_1).compress();

        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);

        let c = transcript.challenge_scalar(b"c");

        let z_x = c * x + y_x;
        let z_0 = c * r_0 + y_0;
        let z_1 = c * r_1 + y_1;

        NetZeroProof {
            Y_0,
            Y_1,
            z_x,
            z_0,
            z_1,
        }
    }

    pub fn verify(
        eg_pk_0: &ElGamalPK,
        eg_pk_1: &ElGamalPK,
        eg_ct_0: &ElGamalCT,
        eg_ct_1: &ElGamalCT,
        transcript: &mut Transcript,
        proof: &NetZeroProof,
    ) -> Result<(), ProofError> {
        transcript.net_zero_domain_sep();

        let H_0 = Some(eg_pk_0.get_point());
        let H_1 = Some(eg_pk_1.get_point());

        let C_0 = Some(eg_ct_0.C_0);
        let C_1 = Some(eg_ct_1.C_0);

        let NetZeroProof {
            Y_0,
            Y_1,
            z_x,
            z_0,
            z_1,
        } = proof;

        transcript.validate_and_append_point(b"Y_0", &Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &Y_1)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.clone().challenge_scalar(b"w");

        let scalars = vec![z_x + w * z_x, *z_0, w * z_1, -c, -w * c, -Scalar::one(), -w];

        let points = vec![
            Some(G),
            H_0,
            H_1,
            C_0,
            C_1,
            Y_0.decompress(),
            Y_1.decompress(),
        ];

        let check = RistrettoPoint::optional_multiscalar_mul(scalars, points)
            .ok_or_else(|| ProofError::VerificationError)?;

        if check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO

        vec![]
    }

    pub fn from_bytes(_slice: &[u8]) -> Result<NetZeroProof, ProofError> {
        // TODO

        Err(ProofError::VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;
    use rand_core::OsRng;

    use crate::elgamal::ElGamal;
    use crate::encode::GroupEncoding;
    use crate::pedersen::Pedersen;

    #[test]
    fn test_prove_verify_correctness() {
        let mut transcript_prover = Transcript::new(b"test");
        let mut transcript_verifier = transcript_prover.clone();

        let amt: u64 = 55;

        let (eg_pk_0, _) = ElGamal::keygen();
        let (eg_pk_1, _) = ElGamal::keygen();

        let eg_rand_0 = ElGamalRand::random(&mut OsRng);
        let eg_rand_1 = ElGamalRand::random(&mut OsRng);

        let eg_ct_0 = ElGamal::encrypt_with(&eg_pk_0, amt, &eg_rand_0);
        let eg_ct_1 = ElGamal::encrypt_with(&eg_pk_1, amt, &eg_rand_1);

        let proof = NetZeroProof::prove(
            amt,
            &eg_pk_0,
            &eg_pk_1,
            &eg_rand_0,
            &eg_rand_1,
            &mut transcript_prover,
            &mut OsRng,
        );

        assert!(NetZeroProof::verify(
            &eg_pk_0,
            &eg_pk_1,
            &eg_ct_0,
            &eg_ct_1,
            &mut transcript_verifier,
            &proof,
        )
        .is_ok());
    }
}
