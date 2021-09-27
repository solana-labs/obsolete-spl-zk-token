///! Instructions provided by the ZkToken Proof program
mod close_account;
pub mod transfer;
mod update_account_pk;
mod withdraw;

pub use {
    close_account::CloseAccountData,
    transfer::{TransferWithRangeProofData, TransferWithValidityProofData},
    update_account_pk::UpdateAccountPkData,
    withdraw::WithdrawData,
};

use {
    crate::{errors::ProofError, id, pod::*},
    bytemuck::Pod,
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive, ToPrimitive},
    solana_program::{instruction::Instruction, pubkey::Pubkey},
};

#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive, PartialEq)]
#[repr(u8)]
pub enum ProofInstruction {
    /// Verify a `UpdateAccountPkData` struct
    ///
    /// Accounts expected by this instruction:
    ///   None
    ///
    /// Data expected by this instruction:
    ///   `UpdateAccountPkData`
    ///
    VerifyUpdateAccountPk,

    /// Verify a `CloseAccountData` struct
    ///
    /// Accounts expected by this instruction:
    ///   None
    ///
    /// Data expected by this instruction:
    ///   `CloseAccountData`
    ///
    VerifyCloseAccount,

    /// Verify a `WithdrawData` struct
    ///
    /// Accounts expected by this instruction:
    ///   None
    ///
    /// Data expected by this instruction:
    ///   `WithdrawData`
    ///
    VerifyWithdraw,

    /// Verify a `TransferWithRangeProofData` struct
    ///
    /// Accounts expected by this instruction:
    ///   None
    ///
    /// Data expected by this instruction:
    ///   `TransferWithRangeProofData`
    ///
    ///
    VerifyTransferWithRangeProofData,

    /// Verify a `TransferWithValidityProofData` struct
    ///
    /// Accounts expected by this instruction:
    ///   None
    ///
    /// Data expected by this instruction:
    ///   `TransferWithValidityProofData`
    ///
    VerifyTransferWithValidityProofData,
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

pub trait Verifiable {
    fn verify(&self) -> Result<(), ProofError>;
}
