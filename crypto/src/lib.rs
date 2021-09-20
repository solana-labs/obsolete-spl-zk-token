#[macro_use]
extern crate bytemuck_derive;

#[macro_use]
pub mod macros;

pub mod encryption;
pub mod errors;
pub mod instructions; // TODO: Rename to `instruction`...
pub mod pod;
pub mod range_proof;
pub mod transcript;

// Program Id of the ZkToken Native Proof program
solana_program::declare_id!("ZkTokenProof1111111111111111111111111111111");
