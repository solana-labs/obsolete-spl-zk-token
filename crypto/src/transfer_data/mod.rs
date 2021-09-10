use merlin::Transcript;
use rand_core::OsRng;

use serde::{Deserialize, Serialize};

use curve25519_dalek::scalar::Scalar;

use crate::elgamal::{ElGamalCT, ElGamalPK, ElGamalRand, ElGamalSK};
use crate::errors::ProofError;
use crate::pedersen::{Pedersen, PedersenComm, PedersenGen};
use crate::transcript::TranscriptProtocol;
use crate::validity_proof::{
    net_proof::NetZeroProof, receiver_ct_proof::AggReceiverCTProof, sender_ct_proof::SenderCTProof,
};

const TWO_32: u64 = 4294967296;

pub trait ProofVerRequired {
    fn verify_proof(&self) -> Result<(), ProofError>;
}

pub struct Temp; // Temporary type

fn split_u64_into_u32(amt: u64) -> (u32, u32) {
    let lo = amt as u32;
    let hi = (amt >> 32) as u32;

    (lo, hi)
}

fn split_u64_into_u16(amt: u64) -> (u16, u16, u16, u16) {
    let amt_0 = amt as u16;
    let amt_1 = (amt >> 16) as u16;
    let amt_2 = (amt >> 32) as u16;
    let amt_3 = (amt >> 48) as u16;

    (amt_0, amt_1, amt_2, amt_3)
}

pub fn combine_u32_ciphertexts(ct_lo: ElGamalCT, ct_hi: ElGamalCT) -> ElGamalCT {
    ct_lo + ct_hi * Scalar::from(TWO_32)
}

#[derive(Deserialize, Serialize)]
pub struct TransDataCTValidity {
    pub sender_pk: ElGamalPK,   // 32
    pub sender_ct: ElGamalCT,   // 64
    pub receiver_pk: ElGamalPK, // 32
    pub receiver_ct: ElGamalCT, // 64

    pub delta_ct_sender: ElGamalCT,                        // 64
    pub rem_comm: PedersenComm,                            // 32
    pub ct_sender_proof: SenderCTProof,                    // 256
    pub delta_ct_receiver: (ElGamalCT, ElGamalCT),         // 128
    pub delta_comm_receiver: (PedersenComm, PedersenComm), // 64
    pub ct_receiver_proof: AggReceiverCTProof,             // 288
}

impl TransDataCTValidity {
    pub fn create(
        amt_spendable: u64,
        amt_delta: u64,
        sender_pk: ElGamalPK,
        sender_sk: ElGamalSK,
        sender_ct: ElGamalCT,
        receiver_pk: ElGamalPK,
        receiver_ct: ElGamalCT,
    ) -> TransDataCTValidity {
        let mut rng = OsRng;
        let mut transcript = Transcript::new(b"transfer tx");

        transcript.append_elgamal_pk(b"sender_pk", &sender_pk);
        transcript.append_elgamal_ct(b"sender_ct", &sender_ct);
        transcript.append_elgamal_pk(b"receiver_pk", &receiver_pk);
        transcript.append_elgamal_ct(b"receiver_ct", &receiver_ct);

        let amt_rem = amt_spendable - amt_delta;
        let (amt_lo, amt_hi) = split_u64_into_u32(amt_delta);

        let sender_rand = ElGamalRand::random(&mut rng);
        let receiver_rand_lo = ElGamalRand::random(&mut rng);
        let receiver_rand_hi = ElGamalRand::random(&mut rng);

        let delta_ct_sender = sender_pk.encrypt_with(amt_delta, &sender_rand);
        let delta_receiver_ct_lo = receiver_pk.encrypt_with(amt_lo, &receiver_rand_lo);
        let delta_receiver_ct_hi = receiver_pk.encrypt_with(amt_hi, &receiver_rand_hi);
        let delta_ct_receiver = (delta_receiver_ct_lo, delta_receiver_ct_hi);
        let rem_ct = sender_ct - delta_ct_sender;

        let (rem_comm, rem_open) = Pedersen::commit(amt_rem);
        let (receiver_comm_lo, receiver_open_lo) = Pedersen::commit(amt_lo);
        let (receiver_comm_hi, receiver_open_hi) = Pedersen::commit(amt_hi);
        let delta_comm_receiver = (receiver_comm_lo, receiver_comm_hi);

        let ct_sender_proof = SenderCTProof::prove(
            amt_delta,
            amt_rem,
            &delta_ct_sender,
            &rem_ct,
            &sender_sk,
            &PedersenGen::default(),
            &rem_open,
            &mut transcript,
            &mut rng,
        );

        let ct_receiver_proof = AggReceiverCTProof::prove(
            (amt_lo, amt_hi),
            &receiver_pk,
            (&receiver_rand_lo, &receiver_rand_hi),
            &PedersenGen::default(),
            (&receiver_open_lo, &receiver_open_hi),
            &mut transcript,
            &mut rng,
        );

        let ct_validity_data = TransDataCTValidity {
            sender_pk,
            sender_ct,
            receiver_pk,
            receiver_ct,

            delta_ct_sender,
            rem_comm,
            ct_sender_proof,
            delta_ct_receiver,
            delta_comm_receiver,
            ct_receiver_proof,
        };

        ct_validity_data
    }
}

impl ProofVerRequired for TransDataCTValidity {
    fn verify_proof(&self) -> Result<(), ProofError> {
        let TransDataCTValidity {
            sender_pk,
            sender_ct,
            receiver_pk,
            receiver_ct,

            delta_ct_sender,
            rem_comm,
            ct_sender_proof,
            delta_ct_receiver,
            delta_comm_receiver,
            ct_receiver_proof,
        } = self;
        let mut transcript = Transcript::new(b"transfer tx");

        transcript.append_elgamal_pk(b"sender_pk", sender_pk);
        transcript.append_elgamal_ct(b"sender_ct", sender_ct);
        transcript.append_elgamal_pk(b"receiver_pk", receiver_pk);
        transcript.append_elgamal_ct(b"receiver_ct", receiver_ct);

        let rem_ct_sender = sender_ct - delta_ct_sender;

        SenderCTProof::verify(
            sender_pk,
            delta_ct_sender,
            &rem_ct_sender,
            &PedersenGen::default(),
            rem_comm,
            &mut transcript,
            ct_sender_proof,
        )?;

        AggReceiverCTProof::verify(
            receiver_pk,
            (&delta_ct_receiver.0, &delta_ct_receiver.1),
            &PedersenGen::default(),
            (&delta_comm_receiver.0, &delta_comm_receiver.1),
            &mut transcript,
            ct_receiver_proof,
        )?;

        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
pub struct TransDataRangeProof {
    pub sender_pk: ElGamalPK,
    pub sender_ct: ElGamalCT,
    pub receiver_pk: ElGamalPK,
    pub receiver_ct: ElGamalCT,

    pub delta_ct_sender: ElGamalCT,                        // 64
    pub rem_comm: PedersenComm,                            // 32
    pub delta_ct_receiver: (ElGamalCT, ElGamalCT),         // 128
    pub delta_comm_receiver: (PedersenComm, PedersenComm), // 64
    pub net_zero_proof: NetZeroProof,
    pub range_proof: RangeProof,
}

impl ProofVerRequired for TransDataRangeProof {
    fn verify_proof(&self) -> Result<(), ProofError> {
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
pub struct RangeProof; // temporary

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::ElGamal;

    #[test]
    fn test_ct_validity_correctness() {
        let amt_spendable: u64 = 77;
        let amt_delta: u64 = 55;
        let amt_receiver: u64 = 0;

        let (sender_pk, sender_sk) = ElGamal::keygen();
        let (receiver_pk, _) = ElGamal::keygen();

        let sender_ct = ElGamal::encrypt(&sender_pk, amt_spendable);
        let receiver_ct = ElGamal::encrypt(&sender_pk, amt_receiver);

        let ct_validity_data = TransDataCTValidity::create(
            amt_spendable,
            amt_delta,
            sender_pk,
            sender_sk,
            sender_ct,
            receiver_pk,
            receiver_ct,
        );

        assert!(ct_validity_data.verify_proof().is_ok());
    }
}
