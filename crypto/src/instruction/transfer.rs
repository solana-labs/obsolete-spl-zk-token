#[cfg(not(target_arch = "bpf"))]
use {
    crate::encryption::{
        elgamal::ElGamalSK,
        pedersen::{Pedersen, PedersenBase, PedersenOpen},
    },
    rand::rngs::OsRng,
};
use {
    crate::{
        instruction::Verifiable,
        encryption::elgamal::{ElGamalCT, ElGamalPK},
        encryption::pedersen::{PedersenComm, PedersenDecHandle},
        errors::ProofError,
        pod::*,
        range_proof::RangeProof,
        transcript::TranscriptProtocol,
    },
    bytemuck::{Pod, Zeroable},
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
    },
    merlin::Transcript,
    std::convert::TryInto,
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

/// The instructions
pub struct TransferWithRangeProof {
    pub proof_component: TransferWithRangeProofData, // 928 bytes
}

pub struct TransferWithValidityProof {
    pub proof_component: TransferWithValidityProofData, // 640 bytes
    pub other_component: OtherComponents,
}

/// Just a grouping struct for the data required for the two transfer instructions. It is
/// convenient to generate the two components jointly as they share common components.
pub struct TransferData {
    pub range_proof_data: TransferWithRangeProofData,
    pub validity_proof_data: TransferWithValidityProofData,
}

impl TransferData {
    #[cfg(not(target_arch = "bpf"))]
    pub fn new(
        transfer_amount: u64,
        spendable_balance: u64,
        spendable_ct: ElGamalCT,
        source_sk: ElGamalSK,
        source_pk: ElGamalPK,
        dest_pk: ElGamalPK,
        auditor_pk: ElGamalPK,
    ) -> Self {
        // split and encrypt transfer amount
        //
        // encryption is a bit more involved since we are generating each components of an ElGamal
        // ciphertext separately.
        let (amount_lo, amount_hi) = split_u64_into_u32(transfer_amount);

        let (comm_lo, open_lo) = Pedersen::commit(amount_lo);
        let (comm_hi, open_hi) = Pedersen::commit(amount_hi);

        let handle_source_lo = source_pk.gen_decrypt_handle(&open_lo);
        let handle_dest_lo = dest_pk.gen_decrypt_handle(&open_lo);
        let handle_auditor_lo = auditor_pk.gen_decrypt_handle(&open_lo);

        let handle_source_hi = source_pk.gen_decrypt_handle(&open_hi);
        let handle_dest_hi = dest_pk.gen_decrypt_handle(&open_hi);
        let handle_auditor_hi = auditor_pk.gen_decrypt_handle(&open_hi);

        // message encoding as Pedersen commitments, which will be included in range proof data
        let amount_comms = TransferComms {
            lo: comm_lo.into(),
            hi: comm_hi.into(),
        };

        // decryption handles, which will be included in the validity proof data
        let decryption_handles_lo = TransferHandles {
            source: handle_source_lo.into(),
            dest: handle_dest_lo.into(),
            auditor: handle_auditor_lo.into(),
        };

        let decryption_handles_hi = TransferHandles {
            source: handle_source_hi.into(),
            dest: handle_dest_hi.into(),
            auditor: handle_auditor_hi.into(),
        };

        // grouping of the public keys for the transfer
        let transfer_public_keys = TransferPubKeys {
            source_pk: source_pk.into(),
            dest_pk: dest_pk.into(),
            auditor_pk: auditor_pk.into(),
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

        // range_proof and validity_proof should be generated together
        let (transfer_proofs, ephemeral_state) = TransferProofs::new(
            &source_sk,
            &source_pk,
            &dest_pk,
            &auditor_pk,
            (amount_lo as u64, amount_hi as u64),
            &open_lo,
            &open_hi,
            new_spendable_balance,
            &new_spendable_ct,
        );

        // generate data components
        let range_proof_data = TransferWithRangeProofData {
            amount_comms,
            proof: transfer_proofs.range_proof,
            ephemeral_state,
        };

        let validity_proof_data = TransferWithValidityProofData {
            decryption_handles_lo,
            decryption_handles_hi,
            transfer_public_keys,
            new_spendable_ct: new_spendable_ct.into(),
            proof: transfer_proofs.validity_proof,
            ephemeral_state,
        };

        TransferData {
            range_proof_data,
            validity_proof_data,
        }
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferWithRangeProofData {
    /// The transfer amount encoded as Pedersen commitments
    pub amount_comms: TransferComms, // 64 bytes

    /// Proof that certifies:
    ///   1. the source account has enough funds for the transfer (i.e. the final balance is a
    ///      64-bit positive number)
    ///   2. the transfer amount is a 64-bit positive number
    pub proof: PodRangeProof128, // 736 bytes

    /// Ephemeral state between the two transfer instruction data
    pub ephemeral_state: TransferEphemeralState, // 128 bytes
}

impl Verifiable for TransferWithRangeProofData {
    fn verify(&self) -> Result<(), ProofError> {
        let mut transcript = Transcript::new(b"TransferWithRangeProof");

        // standard range proof verification
        let proof: RangeProof = self.proof.try_into()?;
        proof.verify_with(
            vec![
                &self.ephemeral_state.spendable_comm_verification.into(),
                &self.amount_comms.lo.into(),
                &self.amount_comms.hi.into(),
            ],
            vec![64_usize, 32_usize, 32_usize],
            Some(self.ephemeral_state.x.into()),
            Some(self.ephemeral_state.z.into()),
            &mut transcript,
        )
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferWithValidityProofData {
    /// The decryption handles that allow decryption of the lo-bits
    pub decryption_handles_lo: TransferHandles, // 96 bytes

    /// The decryption handles that allow decryption of the hi-bits
    pub decryption_handles_hi: TransferHandles, // 96 bytes

    /// The public encryption keys associated with the transfer: source, dest, and auditor
    pub transfer_public_keys: TransferPubKeys, // 96 bytes

    /// The final spendable ciphertext after the transfer
    pub new_spendable_ct: PodElGamalCT, // 64 bytes

    /// Proof that certifies that the decryption handles are generated correctly
    pub proof: ValidityProof, // 160 bytes

    /// Ephemeral state between the two transfer instruction data
    pub ephemeral_state: TransferEphemeralState, // 128 bytes
}

/// The joint data that is shared between the two transfer instructions.
///
/// Identical ephemeral data should be included in the two transfer instructions and this should be
/// checked by the ZK Token program.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferEphemeralState {
    pub spendable_comm_verification: PodPedersenComm, // 32 bytes
    pub x: PodScalar,                                 // 32 bytes
    pub z: PodScalar,                                 // 32 bytes
    pub t_x_blinding: PodScalar,                      // 32 bytes
}

impl Verifiable for TransferWithValidityProofData {
    fn verify(&self) -> Result<(), ProofError> {
        let new_spendable_ct = self.new_spendable_ct.try_into()?;
        let proof = self.proof.clone(); // cloning here for now TODO: figure out how we handle serialization

        proof.verify(
            &new_spendable_ct,
            &self.decryption_handles_lo,
            &self.decryption_handles_hi,
            &self.transfer_public_keys,
            &self.ephemeral_state,
        )
    }
}

/// Other components (like memo?) needed for transfer excluding the crypto components
pub struct OtherComponents;

/// Just a grouping struct for the two proofs that are needed for a transfer instruction. The two
/// proofs have to be generated together as they share joint data.
pub struct TransferProofs {
    pub range_proof: PodRangeProof128,
    pub validity_proof: ValidityProof,
}

#[allow(non_snake_case)]
impl TransferProofs {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::many_single_char_names)]
    #[cfg(not(target_arch = "bpf"))]
    pub fn new(
        source_sk: &ElGamalSK,
        source_pk: &ElGamalPK,
        dest_pk: &ElGamalPK,
        auditor_pk: &ElGamalPK,
        transfer_amt: (u64, u64),
        lo_open: &PedersenOpen,
        hi_open: &PedersenOpen,
        new_spendable_balance: u64,
        new_spendable_ct: &ElGamalCT,
    ) -> (Self, TransferEphemeralState) {
        // TODO: should also commit to pubkeys and commitments later
        let mut transcript_validity_proof = merlin::Transcript::new(b"TransferWithValidityProof");

        let H = PedersenBase::default().H;
        let D = new_spendable_ct.decrypt_handle.get_point();
        let s = source_sk.get_scalar();

        // Generate proof for the new spendable ciphertext
        let r_new = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let R = RistrettoPoint::multiscalar_mul(vec![y, r_new], vec![D, H]).compress();

        transcript_validity_proof.append_point(b"R", &R);
        let c = transcript_validity_proof.challenge_scalar(b"c");

        let z = s + c * y;
        let new_spendable_open = PedersenOpen(c * r_new);

        let spendable_comm_verification =
            Pedersen::commit_with(new_spendable_balance, &new_spendable_open);

        // Generate proof for the transfer amounts
        let t_1_blinding = PedersenOpen::random(&mut OsRng);
        let t_2_blinding = PedersenOpen::random(&mut OsRng);

        let u = transcript_validity_proof.challenge_scalar(b"u");
        let P_joint = RistrettoPoint::multiscalar_mul(
            vec![Scalar::one(), u, u * u],
            vec![
                source_pk.get_point(),
                dest_pk.get_point(),
                auditor_pk.get_point(),
            ],
        );
        let T_joint = (new_spendable_open.get_scalar() * P_joint).compress();
        let T_1 = (t_1_blinding.get_scalar() * P_joint).compress();
        let T_2 = (t_2_blinding.get_scalar() * P_joint).compress();

        transcript_validity_proof.append_point(b"T_1", &T_1);
        transcript_validity_proof.append_point(b"T_2", &T_2);

        // define the validity proof
        let validity_proof = ValidityProof {
            R: R.into(),
            z: z.into(),
            T_joint: T_joint.into(),
            T_1: T_1.into(),
            T_2: T_2.into(),
        };

        // generate the range proof
        let mut transcript_range_proof = Transcript::new(b"TransferWithRangeProof");
        let (range_proof, x, z) = RangeProof::create_with(
            vec![new_spendable_balance, transfer_amt.0, transfer_amt.1],
            vec![64, 32, 32],
            vec![&new_spendable_open, lo_open, hi_open],
            &t_1_blinding,
            &t_2_blinding,
            &mut transcript_range_proof,
        );

        // define ephemeral state
        let ephemeral_state = TransferEphemeralState {
            spendable_comm_verification: spendable_comm_verification.into(),
            x: x.into(),
            z: z.into(),
            t_x_blinding: range_proof.t_x_blinding.into(),
        };

        (
            Self {
                range_proof: range_proof.try_into().expect("valid range_proof"),
                validity_proof,
            },
            ephemeral_state,
        )
    }
}

/// Proof components for transfer instructions.
///
/// These two components should be output by a RangeProof creation function.
#[allow(non_snake_case)]
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ValidityProof {
    // Proof component for the spendable ciphertext components: R
    pub R: PodCompressedRistretto, // 32 bytes
    // Proof component for the spendable ciphertext components: z
    pub z: PodScalar, // 32 bytes
    // Proof component for the transaction amount components: T_src
    pub T_joint: PodCompressedRistretto, // 32 bytes
    // Proof component for the transaction amount components: T_1
    pub T_1: PodCompressedRistretto, // 32 bytes
    // Proof component for the transaction amount components: T_2
    pub T_2: PodCompressedRistretto, // 32 bytes
}

#[allow(non_snake_case)]
impl ValidityProof {
    pub fn verify(
        self,
        new_spendable_ct: &ElGamalCT,
        decryption_handles_lo: &TransferHandles,
        decryption_handles_hi: &TransferHandles,
        transfer_public_keys: &TransferPubKeys,
        ephemeral_state: &TransferEphemeralState,
    ) -> Result<(), ProofError> {
        let mut transcript = Transcript::new(b"TransferWithValidityProof");

        let source_pk: ElGamalPK = transfer_public_keys.source_pk.try_into()?;
        let dest_pk: ElGamalPK = transfer_public_keys.dest_pk.try_into()?;
        let auditor_pk: ElGamalPK = transfer_public_keys.auditor_pk.try_into()?;

        // verify Pedersen commitment in the ephemeral state
        let C_ephemeral: CompressedRistretto = ephemeral_state.spendable_comm_verification.into();

        let C = new_spendable_ct.message_comm.get_point();
        let D = new_spendable_ct.decrypt_handle.get_point();

        let R = self.R.into();
        let z: Scalar = self.z.into();

        transcript.validate_and_append_point(b"R", &R)?;
        let c = transcript.challenge_scalar(b"c");

        let R = R.decompress().ok_or(ProofError::VerificationError)?;

        let spendable_comm_verification =
            RistrettoPoint::multiscalar_mul(vec![Scalar::one(), -z, c], vec![C, D, R]).compress();

        if C_ephemeral != spendable_comm_verification {
            return Err(ProofError::VerificationError);
        }

        // derive joint public key
        let u = transcript.challenge_scalar(b"u");
        let P_joint = RistrettoPoint::vartime_multiscalar_mul(
            vec![Scalar::one(), u, u * u],
            vec![
                source_pk.get_point(),
                dest_pk.get_point(),
                auditor_pk.get_point(),
            ],
        );

        // check well-formedness of decryption handles
        let t_x_blinding: Scalar = ephemeral_state.t_x_blinding.into();
        let T_1: CompressedRistretto = self.T_1.into();
        let T_2: CompressedRistretto = self.T_2.into();

        let x = ephemeral_state.x.into();
        let z: Scalar = ephemeral_state.z.into();

        let handle_source_lo: PedersenDecHandle = decryption_handles_lo.source.try_into()?;
        let handle_dest_lo: PedersenDecHandle = decryption_handles_lo.dest.try_into()?;
        let handle_auditor_lo: PedersenDecHandle = decryption_handles_lo.auditor.try_into()?;

        let D_joint: CompressedRistretto = self.T_joint.into();
        let D_joint = D_joint.decompress().ok_or(ProofError::VerificationError)?;

        let D_joint_lo = RistrettoPoint::vartime_multiscalar_mul(
            vec![Scalar::one(), u, u * u],
            vec![
                handle_source_lo.get_point(),
                handle_dest_lo.get_point(),
                handle_auditor_lo.get_point(),
            ],
        );

        let handle_source_hi: PedersenDecHandle = decryption_handles_hi.source.try_into()?;
        let handle_dest_hi: PedersenDecHandle = decryption_handles_hi.dest.try_into()?;
        let handle_auditor_hi: PedersenDecHandle = decryption_handles_hi.auditor.try_into()?;

        let D_joint_hi = RistrettoPoint::vartime_multiscalar_mul(
            vec![Scalar::one(), u, u * u],
            vec![
                handle_source_hi.get_point(),
                handle_dest_hi.get_point(),
                handle_auditor_hi.get_point(),
            ],
        );

        // TODO: combine Pedersen commitment verification above to here for efficiency
        // TODO: might need to add an additional proof-of-knowledge here (additional 64 byte)
        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            vec![-t_x_blinding, x, x * x, z * z, z * z * z, z * z * z * z],
            vec![
                Some(P_joint),
                T_1.decompress(),
                T_2.decompress(),
                Some(D_joint),
                Some(D_joint_lo),
                Some(D_joint_hi),
            ],
        )
        .ok_or(ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

/// The ElGamal public keys needed for a transfer
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferPubKeys {
    pub source_pk: PodElGamalPK,  // 32 bytes
    pub dest_pk: PodElGamalPK,    // 32 bytes
    pub auditor_pk: PodElGamalPK, // 32 bytes
}

/// The transfer amount commitments needed for a transfer
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferComms {
    pub lo: PodPedersenComm, // 32 bytes
    pub hi: PodPedersenComm, // 32 bytes
}

/// The decryption handles needed for a transfer
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransferHandles {
    pub source: PodPedersenDecHandle,  // 32 bytes
    pub dest: PodPedersenDecHandle,    // 32 bytes
    pub auditor: PodPedersenDecHandle, // 32 bytes
}

/// Split u64 number into two u32 numbers
#[cfg(not(target_arch = "bpf"))]
fn split_u64_into_u32(amt: u64) -> (u32, u32) {
    let lo = amt as u32;
    let hi = (amt >> 32) as u32;

    (lo, hi)
}

/// Constant for 2^32
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::encryption::elgamal::ElGamal;

    #[test]
    fn test_transfer_correctness() {
        // ElGamal keys for source, destination, and auditor accounts
        let (source_pk, source_sk) = ElGamal::keygen();
        let (dest_pk, _) = ElGamal::keygen();
        let (auditor_pk, _) = ElGamal::keygen();

        // create source account spendable ciphertext
        let spendable_balance: u64 = 77;
        let spendable_ct = source_pk.encrypt(spendable_balance);

        // transfer amount
        let transfer_amount: u64 = 55;

        // create transfer data
        let transfer_data = TransferData::new(
            transfer_amount,
            spendable_balance,
            spendable_ct,
            source_sk,
            source_pk,
            dest_pk,
            auditor_pk,
        );

        // verify range proof
        assert!(transfer_data.range_proof_data.verify().is_ok());

        // verify ciphertext validity proof
        assert!(transfer_data.validity_proof_data.verify().is_ok());
    }
}
