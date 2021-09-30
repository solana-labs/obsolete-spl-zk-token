use bytemuck::{Pod, Zeroable};

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct Scalar(pub [u8; 32]);

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct CompressedRistretto(pub [u8; 32]);

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct ElGamalCT(pub [u8; 64]);

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct ElGamalPK(pub [u8; 32]);

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct PedersenComm(pub [u8; 32]);

#[derive(Clone, Copy, Pod, Zeroable, PartialEq)]
#[repr(transparent)]
pub struct PedersenDecHandle(pub [u8; 32]);

/// Serialization of range proofs for 64-bit numbers (for `Withdraw` instruction)
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RangeProof64(pub [u8; 672]);

// `PodRangeProof64` is a Pod and Zeroable.
// Add the marker traits manually because `bytemuck` only adds them for some `u8` arrays
unsafe impl Zeroable for RangeProof64 {}
unsafe impl Pod for RangeProof64 {}

/// Serialization of range proofs for 128-bit numbers (for `TransferRangeProof` instruction)
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RangeProof128(pub [u8; 736]);

// `PodRangeProof128` is a Pod and Zeroable.
// Add the marker traits manually because `bytemuck` only adds them for some `u8` arrays
unsafe impl Zeroable for RangeProof128 {}
unsafe impl Pod for RangeProof128 {}
