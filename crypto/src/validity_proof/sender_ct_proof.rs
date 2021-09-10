use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;

use crate::elgamal::{ElGamalCT, ElGamalPK, ElGamalSK};
use crate::errors::ProofError;
use crate::pedersen::{PedersenComm, PedersenGen, PedersenOpen};
use crate::transcript::TranscriptProtocol;

use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, Deserialize};

#[allow(non_snake_case)]
#[derive(Deserialize, Serialize)]
pub struct SenderCTProof {
    // 256
    Y_sk: CompressedRistretto,      // 32
    Y_x_delta: CompressedRistretto, // 32
    Y_x_rem: CompressedRistretto,   // 32
    Y_p: CompressedRistretto,       // 32
    z_sk: Scalar,                   // 32
    z_x_delta: Scalar,              // 32
    z_x_rem: Scalar,                // 32
    z_p: Scalar,                    // 32
}
#[allow(non_snake_case)]
impl SenderCTProof {
    pub fn prove<T: Into<Scalar>, U: RngCore + CryptoRng>(
        x_delta: T,
        x_rem: T,
        eg_ct_delta: &ElGamalCT,
        eg_ct_rem: &ElGamalCT,
        eg_sk: &ElGamalSK,
        ped_gen: &PedersenGen,
        ped_open: &PedersenOpen,
        transcript: &mut Transcript,
        rng: &mut U,
    ) -> Self {
        transcript.sender_ct_validity_domain_sep();

        let H_p = ped_gen.get_point();
        let C_1_delta = eg_ct_delta.C_1;
        let C_1_rem = eg_ct_rem.C_1;

        let sk = eg_sk.get_scalar();
        let x_delta = x_delta.into();
        let x_rem = x_rem.into();
        let r_p = ped_open.get_scalar();

        let y_sk = Scalar::random(rng);
        let y_x_delta = Scalar::random(rng);
        let y_x_rem = Scalar::random(rng);
        let y_p = Scalar::random(rng);

        let Y_sk = (y_sk * G).compress();
        let Y_x_delta = (y_x_delta * G + y_sk * C_1_delta).compress();
        let Y_x_rem = (y_x_rem * G + y_sk * C_1_rem).compress();
        let Y_p = (y_x_rem * G + y_p * H_p).compress();

        transcript.append_point(b"Y_sk", &Y_sk);
        transcript.append_point(b"Y_x_delta", &Y_x_delta);
        transcript.append_point(b"Y_x_rem", &Y_x_rem);
        transcript.append_point(b"Y_p", &Y_p);

        let c = transcript.challenge_scalar(b"c");

        let z_sk = c * sk + y_sk;
        let z_x_delta = c * x_delta + y_x_delta;
        let z_x_rem = c * x_rem + y_x_rem;
        let z_p = c * r_p + y_p;

        SenderCTProof {
            Y_sk,
            Y_x_delta,
            Y_x_rem,
            Y_p,
            z_sk,
            z_x_delta,
            z_x_rem,
            z_p,
        }
    }

    pub fn verify(
        eg_pk: &ElGamalPK,
        eg_ct_delta: &ElGamalCT,
        eg_ct_rem: &ElGamalCT,
        ped_gen: &PedersenGen,
        ped_comm: &PedersenComm,
        transcript: &mut Transcript,
        proof: &SenderCTProof,
    ) -> Result<(), ProofError> {
        transcript.sender_ct_validity_domain_sep();

        let H_eg = Some(eg_pk.get_point());
        let H_p = Some(ped_gen.get_point());

        let C_0_delta = Some(eg_ct_delta.C_0);
        let C_1_delta = Some(eg_ct_delta.C_1);
        let C_0_rem = Some(eg_ct_rem.C_0);
        let C_1_rem = Some(eg_ct_rem.C_1);
        let comm = Some(ped_comm.get_point());

        let SenderCTProof {
            Y_sk,
            Y_x_delta,
            Y_x_rem,
            Y_p,
            z_sk,
            z_x_delta,
            z_x_rem,
            z_p,
        } = proof;

        transcript.validate_and_append_point(b"Y_sk", &Y_sk)?;
        transcript.validate_and_append_point(b"Y_x_delta", &Y_x_delta)?;
        transcript.validate_and_append_point(b"Y_x_rem", &Y_x_rem)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.clone().challenge_scalar(b"w");
        let ww = w * w;
        let www = ww * w;

        let scalars = vec![
            z_sk + w * z_x_delta + ww * z_x_rem + www * z_x_rem,
            w * z_sk,
            ww * z_sk,
            www * z_p,
            -c,
            -w * c,
            -ww * c,
            -www * c,
            -Scalar::one(),
            -w,
            -ww,
            -www,
        ];

        let points = vec![
            Some(G),
            C_1_delta,
            C_1_rem,
            H_p,
            H_eg,
            C_0_delta,
            C_0_rem,
            comm,
            Y_sk.decompress(),
            Y_x_delta.decompress(),
            Y_x_rem.decompress(),
            Y_p.decompress(),
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

    pub fn from_bytes(_slice: &[u8]) -> Result<SenderCTProof, ProofError> {
        // TODO

        Err(ProofError::VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    use crate::elgamal::ElGamal;
    use crate::pedersen::Pedersen;

    #[test]
    fn test_prove_verify_correctness() {
        let mut transcript_prover = Transcript::new(b"test");
        let mut transcript_verifier = transcript_prover.clone();

        let amt_spendable: u64 = 77;
        let amt_delta: u64 = 55;
        let amt_rem = amt_spendable - amt_delta;

        let (eg_pk, eg_sk) = ElGamal::keygen();
        let eg_ct_spendable = ElGamal::encrypt(&eg_pk, amt_spendable);
        let eg_ct_delta = ElGamal::encrypt(&eg_pk, amt_delta);
        let eg_ct_rem = eg_ct_spendable - eg_ct_delta;

        let ped_gen = PedersenGen::default();
        let (ped_comm, ped_open) = Pedersen::commit(amt_rem);

        let proof = SenderCTProof::prove(
            amt_delta,
            amt_rem,
            &eg_ct_delta,
            &eg_ct_rem,
            &eg_sk,
            &ped_gen,
            &ped_open,
            &mut transcript_prover,
            &mut OsRng,
        );

        assert!(SenderCTProof::verify(
            &eg_pk,
            &eg_ct_delta,
            &eg_ct_rem,
            &ped_gen,
            &ped_comm,
            &mut transcript_verifier,
            &proof,
        )
        .is_ok());
    }
}
