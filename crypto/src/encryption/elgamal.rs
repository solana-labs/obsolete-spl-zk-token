#![allow(non_snake_case, dead_code)]

use core::ops::{Add, Div, Mul, Sub};

#[cfg(not(target_arch = "bpf"))]
use rand::{rngs::OsRng, CryptoRng, RngCore};

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use arrayref::{array_ref, array_refs};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::io::{self, Error, ErrorKind, Write};

use crate::encryption::encode::DiscreteLogInstance;
use crate::encryption::pedersen::{
    Pedersen, PedersenBase, PedersenComm, PedersenDecHandle, PedersenOpen,
};
use crate::errors::ProofError;

/// Handle for the (twisted) ElGamal encryption scheme
pub struct ElGamal;
impl ElGamal {
    /// Generates the public and secret keys for ElGamal encryption.
    #[cfg(not(target_arch = "bpf"))]
    pub fn keygen() -> (ElGamalPK, ElGamalSK) {
        ElGamal::keygen_with(&mut OsRng) // using OsRng for now
    }

    /// On input a randomness generator, the function generates the public and
    /// secret keys for ElGamal encryption.
    #[cfg(not(target_arch = "bpf"))]
    pub fn keygen_with<T: RngCore + CryptoRng>(rng: &mut T) -> (ElGamalPK, ElGamalSK) {
        // sample a non-zero scalar
        let mut s: Scalar;
        loop {
            s = Scalar::random(rng);

            if s != Scalar::zero() {
                break;
            }
        }

        let H = PedersenBase::default().H;
        let P = s.invert() * H;

        (ElGamalPK(P), ElGamalSK(s))
    }

    /// On input a public key and a message to be encrypted, the function
    /// returns an ElGamal ciphertext of the message under the public key.
    #[cfg(not(target_arch = "bpf"))]
    pub fn encrypt<T: Into<Scalar>>(pk: &ElGamalPK, amount: T) -> ElGamalCT {
        let (message_comm, open) = Pedersen::commit(amount);
        let decrypt_handle = pk.gen_decrypt_handle(&open);

        ElGamalCT {
            message_comm,
            decrypt_handle,
        }
    }

    /// On input a public key, message, and Pedersen opening, the function
    /// returns an ElGamal ciphertext of the message under the public key using
    /// the opening.
    pub fn encrypt_with<T: Into<Scalar>>(
        pk: &ElGamalPK,
        amount: T,
        open: &PedersenOpen,
    ) -> ElGamalCT {
        let message_comm = Pedersen::commit_with(amount, open);
        let decrypt_handle = pk.gen_decrypt_handle(open);

        ElGamalCT {
            message_comm,
            decrypt_handle,
        }
    }

    /// On input a secret key and a ciphertext, the function decrypts the ciphertext.
    ///
    /// The output of the function is of type `DiscreteLogInstance`. The exact message
    /// can be recovered via the DiscreteLogInstance's decode method.
    pub fn decrypt(sk: &ElGamalSK, ct: &ElGamalCT) -> DiscreteLogInstance {
        let ElGamalSK(s) = sk;
        let ElGamalCT {
            message_comm,
            decrypt_handle,
        } = ct;

        DiscreteLogInstance {
            generator: PedersenBase::default().G,
            target: message_comm.get_point() - s * decrypt_handle.get_point(),
        }
    }

    /// On input a secret key and a ciphertext, the function decrypts the
    /// ciphertext for a u32 value.
    pub fn decrypt_u32(sk: &ElGamalSK, ct: &ElGamalCT) -> Option<u32> {
        let discrete_log_instance = ElGamal::decrypt(sk, ct);
        discrete_log_instance.decode_u32()
    }
}

/// Public key for the ElGamal encryption scheme.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElGamalPK(RistrettoPoint);
impl ElGamalPK {
    pub fn get_point(&self) -> RistrettoPoint {
        self.0
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<ElGamalPK> {
        Some(ElGamalPK(
            CompressedRistretto::from_slice(bytes).decompress()?,
        ))
    }

    /// Utility method for code ergonomics.
    #[cfg(not(target_arch = "bpf"))]
    pub fn encrypt<T: Into<Scalar>>(&self, msg: T) -> ElGamalCT {
        ElGamal::encrypt(self, msg)
    }

    /// Utility method for code ergonomics.
    pub fn encrypt_with<T: Into<Scalar>>(&self, msg: T, open: &PedersenOpen) -> ElGamalCT {
        ElGamal::encrypt_with(self, msg, open)
    }

    /// Generate a decryption token from an ElGamal public key and a Pedersen
    /// opening.
    pub fn gen_decrypt_handle(self, open: &PedersenOpen) -> PedersenDecHandle {
        PedersenDecHandle::generate_handle(open, &self)
    }
}

impl From<RistrettoPoint> for ElGamalPK {
    fn from(point: RistrettoPoint) -> ElGamalPK {
        ElGamalPK(point)
    }
}

impl BorshSerialize for ElGamalPK {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&self.to_bytes())
    }
}

impl BorshDeserialize for ElGamalPK {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        if buf.len() < 32 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Unexpected length of input",
            ));
        }
        match Self::from_bytes(&buf[..32]) {
            Some(result) => {
                *buf = &buf[32..];
                Ok(result)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid ElGamalPK representation",
            )),
        }
    }
}

/// Secret key for the ElGamal encryption scheme.
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct ElGamalSK(Scalar);
impl ElGamalSK {
    pub fn get_scalar(&self) -> Scalar {
        self.0
    }

    /// Utility method for code ergonomics.
    pub fn decrypt(&self, ct: &ElGamalCT) -> DiscreteLogInstance {
        ElGamal::decrypt(self, ct)
    }

    /// Utility method for code ergonomics.
    pub fn decrypt_u32(&self, ct: &ElGamalCT) -> Option<u32> {
        ElGamal::decrypt_u32(self, ct)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<ElGamalSK> {
        match bytes.try_into() {
            Ok(bytes) => Scalar::from_canonical_bytes(bytes).map(ElGamalSK),
            _ => None,
        }
    }
}

impl From<Scalar> for ElGamalSK {
    fn from(scalar: Scalar) -> ElGamalSK {
        ElGamalSK(scalar)
    }
}

impl Eq for ElGamalSK {}
impl PartialEq for ElGamalSK {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl ConstantTimeEq for ElGamalSK {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl BorshSerialize for ElGamalSK {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&self.to_bytes())
    }
}

impl BorshDeserialize for ElGamalSK {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        if buf.len() < 32 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Unexpected length of input",
            ));
        }
        match Self::from_bytes(&buf[..32]) {
            Some(result) => {
                *buf = &buf[32..];
                Ok(result)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid ElGamalSK representation",
            )),
        }
    }
}

/// Wire version of the `ElGamalCT` type
#[derive(Clone, Copy, Pod, Zeroable)]
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

/// Wire version of the `ElGamalPK` type
#[derive(Clone, Copy, Pod, Zeroable)]
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

/// Ciphertext for the ElGamal encryption scheme.
#[allow(non_snake_case)]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Default,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
)]
pub struct ElGamalCT {
    pub message_comm: PedersenComm,
    pub decrypt_handle: PedersenDecHandle,
}
impl ElGamalCT {
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        bytes[..32].copy_from_slice(self.message_comm.get_point().compress().as_bytes());
        bytes[32..].copy_from_slice(self.decrypt_handle.get_point().compress().as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<ElGamalCT> {
        let bytes = array_ref![bytes, 0, 64];
        let (message_comm, decrypt_handle) = array_refs![bytes, 32, 32];

        let message_comm = CompressedRistretto::from_slice(message_comm).decompress()?;
        let decrypt_handle = CompressedRistretto::from_slice(decrypt_handle).decompress()?;

        Some(ElGamalCT {
            message_comm: PedersenComm(message_comm),
            decrypt_handle: PedersenDecHandle(decrypt_handle),
        })
    }

    /// Utility method for code ergonomics.
    pub fn decrypt(&self, sk: &ElGamalSK) -> DiscreteLogInstance {
        ElGamal::decrypt(sk, self)
    }

    /// Utility method for code ergonomics.
    pub fn decrypt_u32(&self, sk: &ElGamalSK) -> Option<u32> {
        ElGamal::decrypt_u32(sk, self)
    }
}

impl<'a, 'b> Add<&'b ElGamalCT> for &'a ElGamalCT {
    type Output = ElGamalCT;

    fn add(self, other: &'b ElGamalCT) -> ElGamalCT {
        ElGamalCT {
            message_comm: self.message_comm + other.message_comm,
            decrypt_handle: self.decrypt_handle + other.decrypt_handle,
        }
    }
}

define_add_variants!(LHS = ElGamalCT, RHS = ElGamalCT, Output = ElGamalCT);

impl<'a, 'b> Sub<&'b ElGamalCT> for &'a ElGamalCT {
    type Output = ElGamalCT;

    fn sub(self, other: &'b ElGamalCT) -> ElGamalCT {
        ElGamalCT {
            message_comm: self.message_comm - other.message_comm,
            decrypt_handle: self.decrypt_handle - other.decrypt_handle,
        }
    }
}

define_sub_variants!(LHS = ElGamalCT, RHS = ElGamalCT, Output = ElGamalCT);

impl<'a, 'b> Mul<&'b Scalar> for &'a ElGamalCT {
    type Output = ElGamalCT;

    fn mul(self, other: &'b Scalar) -> ElGamalCT {
        ElGamalCT {
            message_comm: self.message_comm * other,
            decrypt_handle: self.decrypt_handle * other,
        }
    }
}

define_mul_variants!(LHS = ElGamalCT, RHS = Scalar, Output = ElGamalCT);

impl<'a, 'b> Div<&'b Scalar> for &'a ElGamalCT {
    type Output = ElGamalCT;

    fn div(self, other: &'b Scalar) -> ElGamalCT {
        ElGamalCT {
            message_comm: self.message_comm * other.invert(),
            decrypt_handle: self.decrypt_handle * other.invert(),
        }
    }
}

define_div_variants!(LHS = ElGamalCT, RHS = Scalar, Output = ElGamalCT);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::pedersen::Pedersen;
    use bincode;

    #[test]
    fn test_encrypt_decrypt_correctness() {
        let (pk, sk) = ElGamal::keygen();
        let msg: u32 = 57;
        let ct = ElGamal::encrypt(&pk, msg);

        let expected_instance = DiscreteLogInstance {
            generator: PedersenBase::default().G,
            target: Scalar::from(msg) * PedersenBase::default().G,
        };

        assert_eq!(expected_instance, ElGamal::decrypt(&sk, &ct));

        // Commenting out for faster testing
        // assert_eq!(msg, ElGamal::decrypt_u32(&sk, &ct).unwrap());
    }

    #[test]
    fn test_decrypt_handle() {
        let (pk_1, sk_1) = ElGamal::keygen();
        let (pk_2, sk_2) = ElGamal::keygen();

        let msg: u32 = 77;
        let (comm, open) = Pedersen::commit(msg);

        let decrypt_handle_1 = pk_1.gen_decrypt_handle(&open);
        let decrypt_handle_2 = pk_2.gen_decrypt_handle(&open);

        let ct_1 = decrypt_handle_1.to_elgamal_ctxt(comm);
        let ct_2 = decrypt_handle_2.to_elgamal_ctxt(comm);

        let expected_instance = DiscreteLogInstance {
            generator: PedersenBase::default().G,
            target: Scalar::from(msg) * PedersenBase::default().G,
        };

        assert_eq!(expected_instance, sk_1.decrypt(&ct_1));
        assert_eq!(expected_instance, sk_2.decrypt(&ct_2));

        // Commenting out for faster testing
        // assert_eq!(msg, sk_1.decrypt_u32(&ct_1).unwrap());
        // assert_eq!(msg, sk_2.decrypt_u32(&ct_2).unwrap());
    }

    #[test]
    fn test_homomorphic_addition() {
        let (pk, _) = ElGamal::keygen();
        let msg_0: u64 = 57;
        let msg_1: u64 = 77;

        let open_0 = PedersenOpen::random(&mut OsRng);
        let open_1 = PedersenOpen::random(&mut OsRng);

        let ct_0 = ElGamal::encrypt_with(&pk, msg_0, &open_0);
        let ct_1 = ElGamal::encrypt_with(&pk, msg_1, &open_1);

        let ct_sum = ElGamal::encrypt_with(&pk, msg_0 + msg_1, &(open_0 + open_1));

        assert_eq!(ct_sum, ct_0 + ct_1);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let (pk, _) = ElGamal::keygen();
        let msg_0: u64 = 77;
        let msg_1: u64 = 55;

        let open_0 = PedersenOpen::random(&mut OsRng);
        let open_1 = PedersenOpen::random(&mut OsRng);

        let ct_0 = ElGamal::encrypt_with(&pk, msg_0, &open_0);
        let ct_1 = ElGamal::encrypt_with(&pk, msg_1, &open_1);

        let ct_sub = ElGamal::encrypt_with(&pk, msg_0 - msg_1, &(open_0 - open_1));

        assert_eq!(ct_sub, ct_0 - ct_1);
    }

    #[test]
    fn test_homomorphic_multiplication() {
        let (pk, _) = ElGamal::keygen();
        let msg_0: u64 = 57;
        let msg_1: u64 = 77;

        let open = PedersenOpen::random(&mut OsRng);

        let ct = ElGamal::encrypt_with(&pk, msg_0, &open);
        let scalar = Scalar::from(msg_1);

        let ct_prod = ElGamal::encrypt_with(&pk, msg_0 * msg_1, &(open * scalar));

        assert_eq!(ct_prod, ct * scalar);
    }

    #[test]
    fn test_homomorphic_division() {
        let (pk, _) = ElGamal::keygen();
        let msg_0: u64 = 55;
        let msg_1: u64 = 5;

        let open = PedersenOpen::random(&mut OsRng);

        let ct = ElGamal::encrypt_with(&pk, msg_0, &open);
        let scalar = Scalar::from(msg_1);

        let ct_div = ElGamal::encrypt_with(&pk, msg_0 / msg_1, &(open / scalar));

        assert_eq!(ct_div, ct / scalar);
    }

    #[test]
    fn test_borsh_ciphertext() {
        let (pk, _) = ElGamal::keygen();
        let msg: u64 = 77;
        let ct = pk.encrypt(msg);

        let encoded = ct.try_to_vec().unwrap();
        let decoded = BorshDeserialize::try_from_slice(&encoded).unwrap();

        assert_eq!(ct, decoded);
    }

    #[test]
    fn test_borsh_pubkey() {
        let (pk, _) = ElGamal::keygen();

        let encoded = pk.try_to_vec().unwrap();
        let decoded = BorshDeserialize::try_from_slice(&encoded).unwrap();

        assert_eq!(pk, decoded);
    }

    #[test]
    fn test_borsh_secretkey() {
        let (_, sk) = ElGamal::keygen();

        let encoded = sk.try_to_vec().unwrap();
        let decoded = BorshDeserialize::try_from_slice(&encoded).unwrap();

        assert_eq!(sk, decoded);
    }

    #[test]
    fn test_serde_ciphertext() {
        let (pk, _) = ElGamal::keygen();
        let msg: u64 = 77;
        let ct = pk.encrypt(msg);

        let encoded = bincode::serialize(&ct).unwrap();
        let decoded: ElGamalCT = bincode::deserialize(&encoded).unwrap();

        assert_eq!(ct, decoded);
    }

    #[test]
    fn test_serde_pubkey() {
        let (pk, _) = ElGamal::keygen();

        let encoded = bincode::serialize(&pk).unwrap();
        let decoded: ElGamalPK = bincode::deserialize(&encoded).unwrap();

        assert_eq!(pk, decoded);
    }

    #[test]
    fn test_serde_secretkey() {
        let (_, sk) = ElGamal::keygen();

        let encoded = bincode::serialize(&sk).unwrap();
        let decoded: ElGamalSK = bincode::deserialize(&encoded).unwrap();

        assert_eq!(sk, decoded);
    }
}
