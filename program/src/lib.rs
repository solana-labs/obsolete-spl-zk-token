//#![deny(missing_docs)]
#![forbid(unsafe_code)]

use {solana_program::pubkey::Pubkey, zeroable::Zeroable};
#[macro_use]
extern crate bytemuck_derive;

mod entrypoint;
pub mod instruction;
pub mod pod;
pub mod processor;
pub mod state;

// ==== crypto placeholders ====
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq)]
#[repr(C)]
pub struct ElGamalPK {
    data: [u8; 32],
}
impl Default for ElGamalPK {
    fn default() -> Self {
        Self { data: [0; 32] }
    }
}
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq)]
#[repr(C)]
pub struct ElGamalCT {
    data: [u8; 64],
}
impl Default for ElGamalCT {
    fn default() -> Self {
        Self { data: [0; 64] }
    }
}
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq)]
#[repr(C)]
pub struct ElGamalSplitCT {
    data_high: [u8; 32],
    data_low: [u8; 32],
}
impl Default for ElGamalSplitCT {
    fn default() -> Self {
        Self {
            data_high: [0; 32],
            data_low: [0; 32],
        }
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransDataCTValidity {
    crypto_stuff: [u8; 512], // TODO
}
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct TransDataRangeProof {
    crypto_stuff: [u8; 512], // TODO
}
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateEncKeyData {
    crypto_stuff: bool,
}
// ==== fin crypto placeholders ====

solana_program::declare_id!("Gcat1YXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNgAse"); // TODO: grind a `CToken...` keypair

pub(crate) fn get_omnibus_token_address_with_seed(spl_token_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[spl_token_mint.as_ref(), br"omnibus"], &id())
}

pub(crate) fn get_transfer_auditor_address_with_seed(spl_token_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[spl_token_mint.as_ref(), br"transfer auditor"], &id())
}

pub(crate) fn get_confidential_address_with_seed(
    spl_token_mint: &Pubkey,
    spl_token_account: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            spl_token_mint.as_ref(),
            spl_token_account.as_ref(),
            br"confidential",
        ],
        &id(),
    )
}

/// Derive the address of the Omnibus SPL Token account for a given SPL Token mint
///
/// The omnibus account is a central token account that holds all SPL Tokens deposited for
/// confidential transfer by users, and is owned by the Confidential Token Program.
///
pub fn get_omnibus_token_address(spl_token_mint: &Pubkey) -> Pubkey {
    get_omnibus_token_address_with_seed(spl_token_mint).0
}

/// Derive the address of the Transfer Auditor account for a given SPL Token mint
///
/// The Transfer Auditor account optionally holds an ElGamal public key for the entity that is
/// authorized to view all confidential transfers for the given SPL Token regardless of receiver.
///
/// Only the SPL Token mint's freeze authority may configure a transfer auditor.
///
pub fn get_transfer_auditor_address(spl_token_mint: &Pubkey) -> Pubkey {
    get_transfer_auditor_address_with_seed(spl_token_mint).0
}

/// Derive the confidential account address for a given SPL Token account address
///
/// This account is created when the token holder executes
/// `ConfidentialTokenInstruction::CreateAccount` to disclose their ElGamal public key
pub fn get_confidential_address(spl_token_mint: &Pubkey, spl_token_account: &Pubkey) -> Pubkey {
    get_confidential_address_with_seed(spl_token_mint, spl_token_account).0
}
