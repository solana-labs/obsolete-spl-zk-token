use core::iter;
use itertools::izip;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;

use crate::elgamal::{ElGamalCT, ElGamalPK, ElGamalRand};
use crate::errors::ProofError;
use crate::pedersen::{PedersenComm, PedersenGen, PedersenOpen};
use crate::transcript::TranscriptProtocol;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Deserialize, Serialize)]
pub struct AggReceiverCTProof {
    pub Y_eg_0: (CompressedRistretto, CompressedRistretto),
    pub Y_eg_1: (CompressedRistretto, CompressedRistretto),
    pub Y_p: (CompressedRistretto, CompressedRistretto),
    pub z_x: Scalar,
    pub z_eg: Scalar,
    pub z_p: Scalar,
}

impl AggReceiverCTProof {
    #[allow(non_snake_case)]
    pub fn prove<T: Into<Scalar>, U: RngCore + CryptoRng>(
        amts: (T, T),
        eg_pk: &ElGamalPK,
        eg_rands: (&ElGamalRand, &ElGamalRand),
        ped_gen: &PedersenGen,
        ped_opens: (&PedersenOpen, &PedersenOpen),
        transcript: &mut Transcript,
        rng: &mut U,
    ) -> Self {
        let ReceiverCTProof {
            Y_eg_0: Y_eg_0_lo,
            Y_eg_1: Y_eg_1_lo,
            Y_p: Y_p_lo,
            z_x: z_x_lo,
            z_eg: z_eg_lo,
            z_p: z_p_lo
        } = ReceiverCTProof::prove(
            amts.0,
            eg_pk,
            eg_rands.0,
            ped_gen,
            ped_opens.0,
            transcript,
            rng,
        );

        let ReceiverCTProof {
            Y_eg_0: Y_eg_0_hi,
            Y_eg_1: Y_eg_1_hi,
            Y_p: Y_p_hi,
            z_x: z_x_hi,
            z_eg: z_eg_hi,
            z_p: z_p_hi,
        } = ReceiverCTProof::prove(
            amts.1,
            eg_pk,
            eg_rands.1,
            ped_gen,
            ped_opens.1,
            transcript,
            rng,
        );

        let t = transcript.challenge_scalar(b"t");

        AggReceiverCTProof {
            Y_eg_0: (Y_eg_0_lo, Y_eg_0_hi),
            Y_eg_1: (Y_eg_1_lo, Y_eg_1_hi),
            Y_p: (Y_p_lo, Y_p_hi),
            z_x: z_x_lo + t * z_x_hi,
            z_eg: z_eg_lo + t * z_eg_hi,
            z_p: z_p_lo + t * z_p_hi,
        }
    }

    #[allow(non_snake_case)]
    pub fn verify(
        eg_pk: &ElGamalPK,
        eg_cts: (&ElGamalCT, &ElGamalCT),
        ped_gen: &PedersenGen,
        ped_comms: (&PedersenComm, &PedersenComm),
        transcript: &mut Transcript,
        proof: &AggReceiverCTProof,
    ) -> Result<(), ProofError> {

        let H_eg = Some(eg_pk.get_point());
        let H_p = Some(ped_gen.get_point());

        let ct_0_lo = Some(eg_cts.0.C_0);
        let ct_1_lo = Some(eg_cts.0.C_1);
        let ct_0_hi = Some(eg_cts.1.C_0);
        let ct_1_hi = Some(eg_cts.1.C_1);

        let comm_lo = Some(ped_comms.0.get_point());
        let comm_hi = Some(ped_comms.1.get_point());

        let AggReceiverCTProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        } = proof;

        transcript.receiver_ct_validity_domain_sep();

        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_0.0)?;
        transcript.validate_and_append_point(b"Y_eg_1", &Y_eg_1.0)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p.0)?;

        let c_lo = transcript.challenge_scalar(b"c");

        transcript.receiver_ct_validity_domain_sep();

        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_0.1)?;
        transcript.validate_and_append_point(b"Y_eg_1", &Y_eg_1.1)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p.1)?;

        let c_hi = transcript.challenge_scalar(b"c");

        let t = transcript.challenge_scalar(b"t");
        let w = transcript.clone().challenge_scalar(b"w");
        let ww = w * w;

        let scalars = vec![
            z_x + w * z_eg + ww * z_x,
            *z_eg,
            ww * z_p,

            -c_lo,
            -t * c_hi,

            -w * c_lo,
            -t * w * c_hi,

            -ww * c_lo,
            -t * ww * c_hi,

            -Scalar::one(),
            -t,

            -w,
            -t * w,

            -ww,
            -t * ww,
        ];

        let points = vec![
            Some(G),
            H_eg,
            H_p,

            ct_0_lo,
            ct_0_hi,

            ct_1_lo,
            ct_1_hi,

            comm_lo,
            comm_hi,

            Y_eg_0.0.decompress(),
            Y_eg_0.1.decompress(),

            Y_eg_1.0.decompress(),
            Y_eg_1.1.decompress(),

            Y_p.0.decompress(),
            Y_p.1.decompress(),
        ];

        let check = RistrettoPoint::optional_multiscalar_mul(scalars, points)
            .ok_or_else(|| ProofError::VerificationError)?;

        if check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

#[allow(non_snake_case)]
pub struct ReceiverCTProof {
    pub Y_eg_0: CompressedRistretto,
    pub Y_eg_1: CompressedRistretto,
    pub Y_p: CompressedRistretto,
    pub z_x: Scalar,
    pub z_eg: Scalar,
    pub z_p: Scalar,
}
impl ReceiverCTProof {
    #[allow(non_snake_case)]
    pub fn prove<T: Into<Scalar>, U: RngCore + CryptoRng>(
        amt: T,
        eg_pk: &ElGamalPK,
        eg_rand: &ElGamalRand,
        ped_gen: &PedersenGen,
        ped_open: &PedersenOpen,
        transcript: &mut Transcript,
        rng: &mut U,
    ) -> Self {
        transcript.receiver_ct_validity_domain_sep();

        let H_eg = eg_pk.get_point();
        let H_p = ped_gen.get_point();

        let x = amt.into();
        let r_eg = eg_rand.get_scalar();
        let r_p = ped_open.get_scalar();

        let y_x = Scalar::random(rng);
        let y_eg = Scalar::random(rng);
        let y_p = Scalar::random(rng);

        let Y_eg_0 = (y_x * G + y_eg * H_eg).compress();
        let Y_eg_1 = (y_eg * G).compress();
        let Y_p = (y_x * G + y_p * H_p).compress();

        transcript.append_point(b"Y_eg_0", &Y_eg_0);
        transcript.append_point(b"Y_eg_1", &Y_eg_1);
        transcript.append_point(b"Y_p", &Y_p);

        let c = transcript.challenge_scalar(b"c");

        let z_x = c * x + y_x;
        let z_eg = c * r_eg + y_eg;
        let z_p = c * r_p + y_p;

        ReceiverCTProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        }
    }

    #[allow(non_snake_case)]
    pub fn verify(
        eg_pk: &ElGamalPK,
        eg_ct: &ElGamalCT,
        ped_gens: &PedersenGen,
        ped_comm: &PedersenComm,
        transcript: &mut Transcript,
        proof: &ReceiverCTProof,
    ) -> Result<(), ProofError> {
        transcript.receiver_ct_validity_domain_sep();

        let H_eg = Some(eg_pk.get_point());
        let H_p = Some(ped_gens.get_point());

        let C_eg_0 = Some(eg_ct.C_0);
        let C_eg_1 = Some(eg_ct.C_1);
        let C_p = Some(ped_comm.get_point());

        let ReceiverCTProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        } = proof;

        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_0)?;
        transcript.validate_and_append_point(b"Y_eg_1", &Y_eg_1)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.clone().challenge_scalar(b"w"); // can otpionally be randomized
        let ww = w * w;

        let scalars = vec![
            z_x + w * z_eg + ww * z_x,
            *z_eg,
            ww * z_p,
            -c,
            -w * c,
            -ww * c,
            -Scalar::one(),
            -w,
            -ww,
        ];

        let points = vec![
            Some(G),
            H_eg,
            H_p,
            C_eg_0,
            C_eg_1,
            C_p,
            Y_eg_0.decompress(),
            Y_eg_1.decompress(),
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

    pub fn from_bytes(_slice: &[u8]) -> Result<AggReceiverCTProof, ProofError> {
        // TODO

        Err(ProofError::VerificationError)
    }
}

/// Provides an iterator over the powers of a `Scalar`.
///
/// This struct is created by the `exp_iter` function.
pub struct ScalarExp {
    x: Scalar,
    next_exp_x: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;

    fn next(&mut self) -> Option<Scalar> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

/// Return an iterator of the powers of `x`.
pub fn exp_iter(x: Scalar) -> ScalarExp {
    let next_exp_x = Scalar::one();
    ScalarExp { x, next_exp_x }
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

        let amt: u16 = 55;

        let (eg_pk, _) = ElGamal::keygen();
        let eg_rand = ElGamalRand::random(&mut OsRng);
        let eg_ct = ElGamal::encrypt_with(&eg_pk, amt, &eg_rand);

        let ped_gen = PedersenGen::default();
        let (ped_comm, ped_open) = Pedersen::commit(amt);

        let proof = ReceiverCTProof::prove(
            amt,
            &eg_pk,
            &eg_rand,
            &ped_gen,
            &ped_open,
            &mut transcript_prover,
            &mut OsRng,
        );

        assert!(ReceiverCTProof::verify(
            &eg_pk,
            &eg_ct,
            &ped_gen,
            &ped_comm,
            &mut transcript_verifier,
            &proof,
        )
        .is_ok());
    }

    #[test]
    fn test_agg_prove_verify_correctness() {
        let mut transcript_prover = Transcript::new(b"test");
        let mut transcript_verifier = transcript_prover.clone();

        let amt_lo: u16 = 55;
        let amt_hi: u16 = 77;

        let (eg_pk, _) = ElGamal::keygen();

        let eg_rand_lo = ElGamalRand::random(&mut OsRng);
        let eg_ct_lo = ElGamal::encrypt_with(&eg_pk, amt_lo, &eg_rand_lo);

        let eg_rand_hi = ElGamalRand::random(&mut OsRng);
        let eg_ct_hi = ElGamal::encrypt_with(&eg_pk, amt_hi, &eg_rand_hi);

        let ped_gen = PedersenGen::default();
        let (ped_comm_lo, ped_open_lo) = Pedersen::commit(amt_lo);
        let (ped_comm_hi, ped_open_hi) = Pedersen::commit(amt_hi);

        let proof = AggReceiverCTProof::prove(
            (amt_lo, amt_hi),
            &eg_pk,
            (&eg_rand_lo, &eg_rand_hi),
            &ped_gen,
            (&ped_open_lo, &ped_open_hi),
            &mut transcript_prover,
            &mut OsRng,
        );

        assert!(AggReceiverCTProof::verify(
            &eg_pk,
            (&eg_ct_lo, &eg_ct_hi),
            &ped_gen,
            (&ped_comm_lo, &ped_comm_hi),
            &mut transcript_verifier,
            &proof
        )
        .is_ok());
    }
}
