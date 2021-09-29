//#![deny(missing_docs)]
#![forbid(unsafe_code)]

use {
    bytemuck::{Zeroable},
    solana_program::pubkey::Pubkey,
};

mod entrypoint;
pub mod instruction;
pub mod pod;
pub mod processor;
pub mod state;

solana_program::declare_id!("ZkTokenXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNg1"); // TODO: grind a `ZkToken...` keypair

pub(crate) fn get_omnibus_token_address_with_seed(spl_token_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[spl_token_mint.as_ref(), br"omnibus"], &id())
}

pub(crate) fn get_transfer_auditor_address_with_seed(spl_token_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[spl_token_mint.as_ref(), br"transfer auditor"], &id())
}

pub(crate) fn get_confidential_token_address_with_seed(
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
pub fn get_confidential_token_address(
    spl_token_mint: &Pubkey,
    spl_token_account: &Pubkey,
) -> Pubkey {
    get_confidential_token_address_with_seed(spl_token_mint, spl_token_account).0
}
