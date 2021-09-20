//! Plain Old Data wrappers for types that need to be sent over the wire
use {
    crate::{
        encryption::elgamal::{ElGamalCT, ElGamalPK},
        encryption::pedersen::{PedersenComm, PedersenDecHandle},
        errors::ProofError,
    },
    curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar},
    std::{convert::TryFrom, fmt},
};

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

// For proof verification, interpret PodPedersenComm as CompressedRistretto
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

