//! Plain Old Data wrappers for `curve25519_dalek` types that need to be sent over the wire
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};

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
