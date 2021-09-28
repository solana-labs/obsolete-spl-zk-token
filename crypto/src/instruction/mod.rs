mod close_account;
pub mod transfer;
mod update_account_pk;
mod withdraw;

pub use {
    close_account::CloseAccountData,
    transfer::{
        TransferComms, TransferData, TransferEphemeralState, TransferPubKeys,
        TransferRangeProofData, TransferValidityProofData,
    },
    update_account_pk::UpdateAccountPkData,
    withdraw::WithdrawData,
};

use crate::errors::ProofError;

pub trait Verifiable {
    fn verify(&self) -> Result<(), ProofError>;
}
