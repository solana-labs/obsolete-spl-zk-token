//! Plain Old Data wrappers for types that need to be sent over the wire
use {
    crate::{
        encryption::elgamal::{ElGamalCT, ElGamalPK},
        encryption::pedersen::{PedersenComm, PedersenDecHandle},
        errors::ProofError,
        range_proof::RangeProof,
    },
    bytemuck::{Pod, Zeroable},
    curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar},
    std::{
        convert::{TryFrom, TryInto},
        fmt,
    },
};

/// Convert a `Pod` into a slice (zero copy)
pub fn pod_bytes_of<T: Pod>(t: &T) -> &[u8] {
    bytemuck::bytes_of(t)
}

/// Convert a slice into a `Pod` (zero copy)
pub fn pod_from_bytes<T: Pod>(bytes: &[u8]) -> Option<&T> {
    bytemuck::try_from_bytes(bytes).ok()
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodScalar([u8; 32]);

impl From<Scalar> for PodScalar {
    fn from(scalar: Scalar) -> Self {
        Self(scalar.to_bytes())
    }
}

impl From<PodScalar> for Scalar {
    fn from(pod: PodScalar) -> Self {
        Scalar::from_bits(pod.0)
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodCompressedRistretto([u8; 32]);

impl From<CompressedRistretto> for PodCompressedRistretto {
    fn from(cr: CompressedRistretto) -> Self {
        Self(cr.to_bytes())
    }
}

impl From<PodCompressedRistretto> for CompressedRistretto {
    fn from(pod: PodCompressedRistretto) -> Self {
        Self(pod.0)
    }
}

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct PodElGamalCT([u8; 64]);
impl From<ElGamalCT> for PodElGamalCT {
    fn from(ct: ElGamalCT) -> Self {
        Self(ct.to_bytes())
    }
}

impl TryFrom<PodElGamalCT> for ElGamalCT {
    type Error = ProofError;

    fn try_from(pod: PodElGamalCT) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod.0).ok_or(ProofError::InconsistentCTData)
    }
}

impl fmt::Debug for PodElGamalCT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct PodElGamalPK([u8; 32]);
impl From<ElGamalPK> for PodElGamalPK {
    fn from(pk: ElGamalPK) -> Self {
        Self(pk.to_bytes())
    }
}

impl TryFrom<PodElGamalPK> for ElGamalPK {
    type Error = ProofError;

    fn try_from(pod: PodElGamalPK) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod.0).ok_or(ProofError::InconsistentCTData)
    }
}

impl fmt::Debug for PodElGamalPK {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct PodPedersenComm([u8; 32]);
impl From<PedersenComm> for PodPedersenComm {
    fn from(comm: PedersenComm) -> Self {
        Self(comm.to_bytes())
    }
}

// For proof verification, interpret PodPedersenComm directly as CompressedRistretto
impl From<PodPedersenComm> for CompressedRistretto {
    fn from(pod: PodPedersenComm) -> Self {
        Self(pod.0)
    }
}

impl TryFrom<PodPedersenComm> for PedersenComm {
    type Error = ProofError;

    fn try_from(pod: PodPedersenComm) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod.0).ok_or(ProofError::InconsistentCTData)
    }
}

impl fmt::Debug for PodPedersenComm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct PodPedersenDecHandle([u8; 32]);
impl From<PedersenDecHandle> for PodPedersenDecHandle {
    fn from(handle: PedersenDecHandle) -> Self {
        Self(handle.to_bytes())
    }
}

// For proof verification, interpret PodPedersenDecHandle as CompressedRistretto
impl From<PodPedersenDecHandle> for CompressedRistretto {
    fn from(pod: PodPedersenDecHandle) -> Self {
        Self(pod.0)
    }
}

impl TryFrom<PodPedersenDecHandle> for PedersenDecHandle {
    type Error = ProofError;

    fn try_from(pod: PodPedersenDecHandle) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod.0).ok_or(ProofError::InconsistentCTData)
    }
}

impl fmt::Debug for PodPedersenDecHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// Serialization of range proofs for 64-bit numbers (for `Withdraw` instruction)
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodRangeProof64([u8; 672]);

// `PodRangeProof64` is a Pod and Zeroable.
// Add the marker traits manually because `bytemuck` only adds them for some `u8` arrays
unsafe impl Zeroable for PodRangeProof64 {}
unsafe impl Pod for PodRangeProof64 {}

impl TryFrom<RangeProof> for PodRangeProof64 {
    type Error = ProofError;

    fn try_from(proof: RangeProof) -> Result<Self, Self::Error> {
        if proof.ipp_proof.serialized_size() != 448 {
            return Err(ProofError::VerificationError);
        }

        let mut buf = [0_u8; 672];
        buf[..32].copy_from_slice(proof.A.as_bytes());
        buf[32..64].copy_from_slice(proof.S.as_bytes());
        buf[64..96].copy_from_slice(proof.T_1.as_bytes());
        buf[96..128].copy_from_slice(proof.T_2.as_bytes());
        buf[128..160].copy_from_slice(proof.t_x.as_bytes());
        buf[160..192].copy_from_slice(proof.t_x_blinding.as_bytes());
        buf[192..224].copy_from_slice(proof.e_blinding.as_bytes());
        buf[224..672].copy_from_slice(&proof.ipp_proof.to_bytes());
        Ok(PodRangeProof64(buf))
    }
}

impl TryFrom<PodRangeProof64> for RangeProof {
    type Error = ProofError;

    fn try_from(pod: PodRangeProof64) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod.0)
    }
}

/// Serialization of range proofs for 128-bit numbers (for `TransferRangeProof` instruction)
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodRangeProof128([u8; 736]);

// `PodRangeProof128` is a Pod and Zeroable.
// Add the marker traits manually because `bytemuck` only adds them for some `u8` arrays
unsafe impl Zeroable for PodRangeProof128 {}
unsafe impl Pod for PodRangeProof128 {}

impl TryFrom<RangeProof> for PodRangeProof128 {
    type Error = ProofError;

    fn try_from(proof: RangeProof) -> Result<Self, Self::Error> {
        if proof.ipp_proof.serialized_size() != 512 {
            return Err(ProofError::VerificationError);
        }

        let mut buf = [0_u8; 736];
        buf[..32].copy_from_slice(proof.A.as_bytes());
        buf[32..64].copy_from_slice(proof.S.as_bytes());
        buf[64..96].copy_from_slice(proof.T_1.as_bytes());
        buf[96..128].copy_from_slice(proof.T_2.as_bytes());
        buf[128..160].copy_from_slice(proof.t_x.as_bytes());
        buf[160..192].copy_from_slice(proof.t_x_blinding.as_bytes());
        buf[192..224].copy_from_slice(proof.e_blinding.as_bytes());
        buf[224..736].copy_from_slice(&proof.ipp_proof.to_bytes());
        Ok(PodRangeProof128(buf))
    }
}

impl TryFrom<PodRangeProof128> for RangeProof {
    type Error = ProofError;

    fn try_from(pod: PodRangeProof128) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod.0)
    }
}

// Arithmetic functions on PodElGamalCT's.
//
// The conversion PodElGamalCT --> ElGamalCT require the use of
//      CompressedRistretto::decompress(&self) -> Option<RistrettoPoint>
//
// which is about 310k BPF instructions. Hence, we need syscalls for the following functions for
// the ZK Token program to add/subtract balances without needing to do type conversion as BPF
// instructions.
//
// This is regarding the discussion:
//  https://discord.com/channels/428295358100013066/774014770402689065/880529250246082611
//
pub fn add_pod_ciphertexts(
    ct_0: PodElGamalCT,
    ct_1: PodElGamalCT,
) -> Result<PodElGamalCT, ProofError> {
    let ct_0: ElGamalCT = ct_0.try_into()?;
    let ct_1: ElGamalCT = ct_1.try_into()?;

    let ct_sum = ct_0 + ct_1;
    Ok(ct_sum.into())
}

pub fn sub_pod_ciphertexts(
    ct_0: PodElGamalCT,
    ct_1: PodElGamalCT,
) -> Result<PodElGamalCT, ProofError> {
    let ct_0: ElGamalCT = ct_0.try_into()?;
    let ct_1: ElGamalCT = ct_1.try_into()?;

    let ct_sum = ct_0 - ct_1;
    Ok(ct_sum.into())
}

pub fn add_to_pod_ciphertext(ct: PodElGamalCT, amount: u64) -> Result<PodElGamalCT, ProofError> {
    let ct: ElGamalCT = ct.try_into()?;
    let ct_sum = ct.add_to_msg(amount);
    Ok(ct_sum.into())
}

pub fn sub_to_pod_ciphertext(ct: PodElGamalCT, amount: u64) -> Result<PodElGamalCT, ProofError> {
    let ct: ElGamalCT = ct.try_into()?;
    let ct_sub = ct.sub_to_msg(amount);
    Ok(ct_sub.into())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::encryption::{
            elgamal::{ElGamal, ElGamalCT},
            pedersen::{Pedersen, PedersenOpen},
        },
        merlin::Transcript,
        rand::rngs::OsRng,
        std::convert::TryInto,
    };

    #[test]
    fn test_zero_ct() {
        let spendable_balance = PodElGamalCT::zeroed();
        let spendable_ct: ElGamalCT = spendable_balance.try_into().unwrap();

        // spendable_ct should be an encryption of 0 for any public key when
        // `PedersenOpen::default()` is used
        let (pk, _) = ElGamal::keygen();
        let balance: u64 = 0;
        assert_eq!(
            spendable_ct,
            pk.encrypt_with(balance, &PedersenOpen::default())
        );

        // homomorphism should work like any other ciphertext
        let open = PedersenOpen::random(&mut OsRng);
        let transfer_amount_ct = pk.encrypt_with(55_u64, &open);
        let transfer_amount_pod: PodElGamalCT = transfer_amount_ct.into();

        let sum = crate::pod::add_pod_ciphertexts(spendable_balance, transfer_amount_pod).unwrap();

        let expected: PodElGamalCT = pk.encrypt_with(55_u64, &open).into();
        assert_eq!(expected, sum);
    }

    #[test]
    fn test_pod_range_proof_64() {
        let (comm, open) = Pedersen::commit(55_u64);

        let mut transcript_create = Transcript::new(b"Test");
        let mut transcript_verify = Transcript::new(b"Test");

        let proof = RangeProof::create(vec![55], vec![64], vec![&open], &mut transcript_create);

        let proof_serialized: PodRangeProof64 = proof.try_into().unwrap();
        let proof_deserialized: RangeProof = proof_serialized.try_into().unwrap();

        assert!(proof_deserialized
            .verify(
                vec![&comm.get_point().compress()],
                vec![64],
                &mut transcript_verify
            )
            .is_ok());

        // should fail to serialize to PodRangeProof128
        let proof = RangeProof::create(vec![55], vec![64], vec![&open], &mut transcript_create);

        assert!(TryInto::<PodRangeProof128>::try_into(proof).is_err());
    }

    #[test]
    fn test_pod_range_proof_128() {
        let (comm_1, open_1) = Pedersen::commit(55_u64);
        let (comm_2, open_2) = Pedersen::commit(77_u64);
        let (comm_3, open_3) = Pedersen::commit(99_u64);

        let mut transcript_create = Transcript::new(b"Test");
        let mut transcript_verify = Transcript::new(b"Test");

        let proof = RangeProof::create(
            vec![55, 77, 99],
            vec![64, 32, 32],
            vec![&open_1, &open_2, &open_3],
            &mut transcript_create,
        );

        let comm_1_point = comm_1.get_point().compress();
        let comm_2_point = comm_2.get_point().compress();
        let comm_3_point = comm_3.get_point().compress();

        let proof_serialized: PodRangeProof128 = proof.try_into().unwrap();
        let proof_deserialized: RangeProof = proof_serialized.try_into().unwrap();

        assert!(proof_deserialized
            .verify(
                vec![&comm_1_point, &comm_2_point, &comm_3_point],
                vec![64, 32, 32],
                &mut transcript_verify,
            )
            .is_ok());

        // should fail to serialize to PodRangeProof64
        let proof = RangeProof::create(
            vec![55, 77, 99],
            vec![64, 32, 32],
            vec![&open_1, &open_2, &open_3],
            &mut transcript_create,
        );

        assert!(TryInto::<PodRangeProof64>::try_into(proof).is_err());
    }
}
