use {
    crate::{
        encryption::elgamal::{ElGamalCT, ElGamalPK},
        encryption::pedersen::{PedersenComm, PedersenDecHandle},
        range_proof::RangeProof,
    },
    curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar},
};
#[cfg(not(target_arch = "bpf"))]
use {
    crate::{
        encryption::{
            elgamal::ElGamalSK,
            pedersen::{Pedersen, PedersenBase, PedersenOpen},
        },
        transcript::TranscriptProtocol,
    },
    rand::rngs::OsRng,
};

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
    pub proof_component: TransferWithRangeProofData,
}

pub struct TransferWithValidityProof {
    pub proof_component: TransferWithValidityProofData,
    pub other_component: OtherComponents,
}

pub struct TransferWithRangeProofData {
    /// The transfer amount encoded as Pedersen commitments
    pub amount_comms: TransferComms,

    /// The Pedersen commitment component of the source account spendable balance
    pub spendable_comm: PedersenComm,

    /// Proof that certifies:
    ///   1. the source account has enough funds for the transfer
    ///   2. the transfer amount is a 64-bit positive number
    pub proof: RangeProof,
}

pub struct TransferWithValidityProofData {
    /// The decryption handles that allow decryption of the lo-bits
    pub decryption_handles_lo: TransferHandles,

    /// The decryption handles that allow decryption of the hi-bits
    pub decryption_handles_hi: TransferHandles,

    /// The public encryption keys associated with the transfer: source, dest, and auditor
    pub transfer_public_keys: TransferPubKeys,

    /// Proof that certifies that the decryption handles are generated correctly
    pub proof: ValidityProof,
}

#[cfg(not(target_arch = "bpf"))]
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

    let handle_source_lo = source_pk.gen_decrypt_handle(&open_lo);
    let handle_dest_lo = dest_pk.gen_decrypt_handle(&open_lo);
    let handle_auditor_lo = auditor_pk.gen_decrypt_handle(&open_lo);

    let handle_source_hi = source_pk.gen_decrypt_handle(&open_hi);
    let handle_dest_hi = dest_pk.gen_decrypt_handle(&open_hi);
    let handle_auditor_hi = auditor_pk.gen_decrypt_handle(&open_hi);

    let amount_comms = TransferComms {
        lo: comm_lo,
        hi: comm_hi,
    };

    let decryption_handles_lo = TransferHandles {
        source: handle_source_lo,
        dest: handle_dest_lo,
        auditor: handle_auditor_lo,
    };

    let decryption_handles_hi = TransferHandles {
        source: handle_source_hi,
        dest: handle_dest_hi,
        auditor: handle_auditor_hi,
    };

    // subtract transfer amount from the spendable ciphertext
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
    //
    // range_proof and validity_proof should be generated together
    let (range_proof, validity_proof) = transfer_proof_create(
        &source_sk,
        &dest_pk,
        (amount_lo as u64, amount_hi as u64),
        &amount_comms,
        &open_lo,
        &open_hi,
        new_spendable_balance,
        &new_spendable_ct,
    );

    // generate data components
    let range_proof_data = TransferWithRangeProofData {
        amount_comms,
        spendable_comm: new_spendable_comm,
        proof: range_proof,
    };

    let validity_proof_data = TransferWithValidityProofData {
        decryption_handles_lo,
        decryption_handles_hi,
        transfer_public_keys,
        proof: validity_proof,
    };

    // generate instruction
    let transfer_range_proof = TransferWithRangeProof {
        proof_component: range_proof_data,
    };

    let transfer_proof_create = TransferWithValidityProof {
        proof_component: validity_proof_data,
        other_component: OtherComponents,
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
    // Proof component for the spendable ciphertext components: R
    pub R: CompressedRistretto,
    // Proof component for the spendable ciphertext components: z
    pub z: Scalar,
    // Proof component for the transaction amount components: T_1
    pub T_1: CompressedRistretto,
    // Proof component for the transaction amount components: T_2
    pub T_2: CompressedRistretto,
}

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[cfg(not(target_arch = "bpf"))]
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
    let mut transcript = merlin::Transcript::new(b"Solana CToken on testnet: Transfer");

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

#[cfg(not(target_arch = "bpf"))]
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
