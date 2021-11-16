//#![deny(missing_docs)]
#![forbid(unsafe_code)]

use {bytemuck::Zeroable, solana_program::pubkey::Pubkey};

mod entrypoint;
pub mod instruction;
pub mod pod;
pub mod processor;
pub mod state;

solana_program::declare_id!("ZkTokenXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNg1"); // TODO: grind a `ZkToken...` keypair

pub(crate) fn get_omnibus_token_address_with_seed(token_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[token_mint.as_ref(), br"omnibus"], &id())
}

pub(crate) fn get_zk_mint_address_with_seed(token_mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[token_mint.as_ref(), br"zk_mint"], &id())
}

pub(crate) fn get_zk_token_address_with_seed(
    token_mint: &Pubkey,
    token_account: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[token_mint.as_ref(), token_account.as_ref(), br"zk_account"],
        &id(),
    )
}

/// Derive the address of the Omnibus SPL Token account for a given SPL Token mint
///
/// The omnibus account is a central token account that holds all SPL Tokens deposited for
/// confidential transfer by users, and is owned by the Confidential Token Program.
///
pub fn get_omnibus_token_address(token_mint: &Pubkey) -> Pubkey {
    get_omnibus_token_address_with_seed(token_mint).0
}

/// Derive the address of the zk mint for a given SPL Token mint
///
/// The Auditor account optionally holds an ElGamal public key for the entity that is
/// authorized to view all confidential transfers for the given SPL Token regardless of receiver.
///
/// Only the SPL Token mint's freeze authority may configure an auditor.
///
pub fn get_zk_mint_address(token_mint: &Pubkey) -> Pubkey {
    get_zk_mint_address_with_seed(token_mint).0
}

/// Derive the zk account address for a given SPL Token account address
///
/// This account is created when the token holder executes
/// `ZkTokenInstruction::ConfigureAccount` to disclose their ElGamal public key
pub fn get_zk_token_address(token_mint: &Pubkey, token_account: &Pubkey) -> Pubkey {
    get_zk_token_address_with_seed(token_mint, token_account).0
}
