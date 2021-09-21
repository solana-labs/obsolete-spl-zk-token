///! Instructions provided by the ZkToken Proof program
pub mod close_account; // TODO: remove pub
pub mod transfer; // TODO: remove pub
mod update_account_pk;
pub mod withdraw; // TODO: remove pub

pub use update_account_pk::UpdateAccountPkData;

use {
    crate::{id, pod::*},
    bytemuck::Pod,
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive, ToPrimitive},
    solana_program::{instruction::Instruction, pubkey::Pubkey},
    zeroable::Zeroable,
};

#[derive(Clone, Copy, Debug, Zeroable, FromPrimitive, ToPrimitive, PartialEq)]
#[repr(u8)]
pub enum ProofInstruction {
    /// Verify an `UpdateAccountPkData` proof
    ///
    /// Accounts expected by this instruction:
    ///   None
    ///
    /// Data expected by this instruction:
    ///   `update_account_pk::UpdateAccountPkData`
    ///
    VerifyUpdateAccountPkData,
}

impl ProofInstruction {
    pub fn encode<T: Pod>(&self, proof: &T) -> Instruction {
        let mut data = vec![ToPrimitive::to_u8(self).unwrap()];
        data.extend_from_slice(pod_bytes_of(proof));
        Instruction {
            program_id: id(),
            accounts: vec![],
            data,
        }
    }

    pub fn decode_type(program_id: &Pubkey, input: &[u8]) -> Option<Self> {
        if *program_id != id() || input.is_empty() {
            None
        } else {
            FromPrimitive::from_u8(input[0])
        }
    }

    pub fn decode_data<T: Pod>(input: &[u8]) -> Option<&T> {
        if input.is_empty() {
            None
        } else {
            pod_from_bytes(&input[1..])
        }
    }
}
