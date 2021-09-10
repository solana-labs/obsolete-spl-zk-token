use merlin::Transcript;
use rand_core::OsRng;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::encryption::elgamal::{ElGamalCT, ElGamalPK, ElGamalSK};
use crate::encryption::pedersen::{
    Pedersen, PedersenBase, PedersenComm, PedersenDecHandle, PedersenOpen,
};
use crate::range_proof::RangeProof;
use crate::transcript::TranscriptProtocol;

/// NOTE: I think the logical way to divide up the proof is as before:
/// 1. rangeproof
/// 2. ciphertext validity proof
///
/// We can have transfer instructions for each of these proof components.
/// - Rangeproof is going to be the much heavier component in terms of size and verification cost.
/// - Ciphertext validity proof should be relatively lightweight and small so there should be room
///   to fit other things in the same instruction.
///

pub struct TransferWithRangeProof {
    pub amount_comms: TransferComms,
    pub proof_component: RangeProofData,
}

pub struct TransferWithValidityProof {
    pub decryption_handles_lo: TransferHandles,
    pub decryption_handles_hi: TransferHandles,
    pub proof_component: ValidityProofData,
    pub memo_component: OtherComponents,
}

pub struct RangeProofData {
    pub spendable_comm: PedersenComm,

    pub proof: RangeProof,
}

pub struct ValidityProofData {
    pub transfer_public_keys: TransferPubKeys,

    pub proof: ValidityProof,
}

pub fn create_transfer_instruction(
    transfer_amount: u64,
    spendable_balance: u64,
    spendable_ct: ElGamalCT,
    source_pk: ElGamalPK,
    source_sk: ElGamalSK,
    dest_pk: ElGamalPK,
    auditor_pk: ElGamalPK,
) -> (TransferWithRangeProof, TransferWithValidityProof) {
    let transfer_public_keys = TransferPubKeys {
        source_pk,
        dest_pk,
        auditor_pk,
    };

    // split and encrypt transfer amount
    let (amount_lo, amount_hi) = split_u64_into_u32(transfer_amount);

    let (comm_lo, open_lo) = Pedersen::commit(amount_lo);
    let (comm_hi, open_hi) = Pedersen::commit(amount_hi);

    let handle_source_lo = PedersenDecHandle::generate_handle(&open_lo, &source_pk);
    let handle_dest_lo = PedersenDecHandle::generate_handle(&open_lo, &dest_pk);
    let handle_auditor_lo = PedersenDecHandle::generate_handle(&open_lo, &auditor_pk);

    let handle_source_hi = PedersenDecHandle::generate_handle(&open_hi, &source_pk);
    let handle_dest_hi = PedersenDecHandle::generate_handle(&open_hi, &dest_pk);
    let handle_auditor_hi = PedersenDecHandle::generate_handle(&open_hi, &auditor_pk);

    let transfer_comms = TransferComms {
        lo: comm_lo,
        hi: comm_hi,
    };

    let lo_transfer_handles = TransferHandles {
        source: handle_source_lo,
        dest: handle_dest_lo,
        auditor: handle_auditor_lo,
    };

    let hi_transfer_handles = TransferHandles {
        source: handle_source_hi,
        dest: handle_dest_hi,
        auditor: handle_auditor_hi,
    };

    // subtract to spendable comm
    let spendable_comm = spendable_ct.message_comm;
    let spendable_handle = spendable_ct.decrypt_handle;

    let new_spendable_balance = spendable_balance - transfer_amount;
    let new_spendable_comm = spendable_comm - combine_u32_comms(comm_lo, comm_hi);
    let new_spendable_handle =
        spendable_handle - combine_u32_handles(handle_source_lo, handle_source_hi);

    let new_spendable_ct = ElGamalCT {
        message_comm: new_spendable_comm,
        decrypt_handle: new_spendable_handle,
    };

    // generate proofs
    let (range_proof, validity_proof) = transfer_proof_create(
        &source_sk,
        &dest_pk,
        (amount_lo as u64, amount_hi as u64),
        &transfer_comms,
        &open_lo,
        &open_hi,
        new_spendable_balance,
        &new_spendable_ct,
    );

    // generate data components
    let range_proof_data = RangeProofData {
        spendable_comm: new_spendable_comm,
        proof: range_proof,
    };

    let validity_proof_data = ValidityProofData {
        transfer_public_keys,
        proof: validity_proof,
    };

    // generate instruction
    let transfer_range_proof = TransferWithRangeProof {
        amount_comms: transfer_comms,
        proof_component: range_proof_data,
    };

    let transfer_proof_create = TransferWithValidityProof {
        decryption_handles_lo: lo_transfer_handles,
        decryption_handles_hi: hi_transfer_handles,
        proof_component: validity_proof_data,
        memo_component: OtherComponents,
    };

    (transfer_range_proof, transfer_proof_create)
}

/// Other components needed for transfer excluding the crypto components
pub struct OtherComponents;

/// Proof components for transfer instructions.
///
/// These two components should be output by a RangeProof creation function.
#[allow(non_snake_case)]
pub struct ValidityProof {
    // Proof components for the spendable ciphertext components
    pub R: CompressedRistretto,
    pub z: Scalar,

    // Proof for the transaction amount components
    pub T_1: CompressedRistretto,
    pub T_2: CompressedRistretto,
}

#[allow(non_snake_case)]
fn transfer_proof_create(
    source_sk: &ElGamalSK,

    dest_pk: &ElGamalPK,

    transfer_amt: (u64, u64),
    transfer_comms: &TransferComms,
    lo_open: &PedersenOpen,
    hi_open: &PedersenOpen,

    spendable_balance: u64,
    spendable_ct: &ElGamalCT,
) -> (RangeProof, ValidityProof) {
    let mut transcript = Transcript::new(b"Solana CToken on testnet: Transfer");

    let H = PedersenBase::default().H;

    let D = spendable_ct.decrypt_handle.get_point();

    let s = source_sk.get_scalar();

    // Generate proof for the new spenable ciphertext
    let r_new = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);
    let R = (y * D + r_new * H).compress();

    transcript.append_point(b"R", &R);
    let c = transcript.challenge_scalar(b"c");

    let z = c * s + y;
    let spendable_open = PedersenOpen(c * r_new);
    //let spendable_comm = Pedersen::commit_with(spendable_balance, &spendable_open);

    // Generate proof for the transfer amounts
    let t_1_blinding = PedersenOpen::random(&mut OsRng);
    let t_2_blinding = PedersenOpen::random(&mut OsRng);

    let range_proof = RangeProof::create(
        vec![spendable_balance, transfer_amt.0, transfer_amt.1],
        vec![64, 32, 32],
        vec![
            &spendable_ct.message_comm,
            &transfer_comms.lo,
            &transfer_comms.hi,
        ],
        vec![&spendable_open, lo_open, hi_open],
        &t_1_blinding,
        &t_2_blinding,
        &mut transcript,
    );

    // Generate aggregated range proof
    let T_1 = t_1_blinding.get_scalar() * dest_pk.get_point();
    let T_2 = t_2_blinding.get_scalar() * dest_pk.get_point();

    let T_1 = T_1.compress();
    let T_2 = T_2.compress();

    transcript.append_point(b"T_1", &T_1);
    transcript.append_point(b"T_2", &T_2);

    let validity_proof = ValidityProof { R, z, T_1, T_2 };

    (range_proof, validity_proof)
}

/// The ElGamal public keys needed for a transfer
pub struct TransferPubKeys {
    pub source_pk: ElGamalPK,
    pub dest_pk: ElGamalPK,
    pub auditor_pk: ElGamalPK,
}

/// The transfer amount commitments needed for a transfer
pub struct TransferComms {
    pub lo: PedersenComm,
    pub hi: PedersenComm,
}

/// The decryption handles needed for a transfer
pub struct TransferHandles {
    pub source: PedersenDecHandle,
    pub dest: PedersenDecHandle,
    pub auditor: PedersenDecHandle,
}

fn split_u64_into_u32(amt: u64) -> (u32, u32) {
    let lo = amt as u32;
    let hi = (amt >> 32) as u32;

    (lo, hi)
}

const TWO_32: u64 = 4294967296;

pub fn combine_u32_comms(comm_lo: PedersenComm, comm_hi: PedersenComm) -> PedersenComm {
    comm_lo + comm_hi * Scalar::from(TWO_32)
}

pub fn combine_u32_handles(
    handle_lo: PedersenDecHandle,
    handle_hi: PedersenDecHandle,
) -> PedersenDecHandle {
    handle_lo + handle_hi * Scalar::from(TWO_32)
}

pub fn combine_u32_ciphertexts(ct_lo: ElGamalCT, ct_hi: ElGamalCT) -> ElGamalCT {
    ct_lo + ct_hi * Scalar::from(TWO_32)
}
