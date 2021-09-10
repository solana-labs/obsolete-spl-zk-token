use merlin::Transcript;
use rand_core::OsRng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul};

use crate::encryption::elgamal::{ElGamal, ElGamalCT, ElGamalPK, ElGamalSK};
use crate::encryption::pedersen::PedersenOpen;
use crate::errors::ProofError;
use crate::transcript::TranscriptProtocol;

/// Withdraw SPL Tokens from the available balance of a confidential token account.
///
/// Fails if the source or destination accounts are frozen.
///
/// Accounts expected by this instruction:
///
///   0. `[writable]` The source confidential token account
///   1. `[]` The source's corresponding SPL token account
///   2. `[writable]` The destination SPL Token account
///   3. `[]` The token mint.
///   4. `[writable]` The omnibus SPL Token account for this token mint, computed by `get_omnibus_token_address()`
///   5. `[]` SPL Token program
///   6. `[signer]` The single source account owner
/// or:
///   6. `[]` The multisig  source account owner
///   7.. `[signer]` Required M signer accounts for the SPL Token Multisig account
///
/// Implementing it here as a struct for demonstration
#[allow(dead_code)]
struct Withdraw {
    /// The amount of tokens to withdraw.
    amount: u64,
    /// Expected number of base 10 digits to the right of the decimal place.
    decimals: u8,
    /// TODO: Proof that the encrypted balance is >= `amount`
    proof_component: WithdrawProofData,
}

/// This struct includes the cryptographic proof *and* the account data information needed to verify
/// the proof
///
/// - The pre-instruction should call WithdrawData::verify_proof(&self)
/// - The actual program should check that `current_ct` is consistent with what is
///   currently stored in the confidential token account TODO: update
///
pub struct WithdrawProofData {
    /// The source account ElGamal public key
    pub source_pk: ElGamalPK,
    /// The source account available balance *after* the withdraw (encrypted by
    /// `source_pk`)
    pub source_final_balance: ElGamalCT,
    /// Proof that the account is solvent
    pub proof: WithdrawProof,
}

impl WithdrawProofData {
    pub fn create(
        amount: u64,
        source_pk: &ElGamalPK,
        source_sk: &ElGamalSK,
        source_current_balance: &ElGamalCT,
    ) -> Self {
        // generate a new transcript
        let mut transcript = Transcript::new(b"Solana CToken on testnet: WithdrawData");

        // encode withdraw amount as an ElGamal ciphertext and subtract it from
        // current source balance
        let amount_encoded = ElGamal::encrypt_with(source_pk, amount, &PedersenOpen::default());
        let source_final_balance = source_current_balance - amount_encoded;

        // create proof of solvency
        let proof = WithdrawProof::create(
            amount,
            source_pk,
            source_sk,
            &source_final_balance,
            &mut transcript,
        );

        WithdrawProofData {
            source_pk: *source_pk,
            source_final_balance,
            proof,
        }
    }

    /// Verifies the WithdrawData proof.
    pub fn verify_proof(amount: u64) -> Result<(), ProofError> {
        // TODO
        Ok(())
    }
}

/// This struct represents the cryptographic proof component that certifies the account's solvency
/// for withdrawal
#[allow(non_snake_case)]
pub struct WithdrawProof {}

#[allow(non_snake_case)]
impl WithdrawProof {
    pub fn create(
        _amount: u64,
        _source_pk: &ElGamalPK,
        _source_sk: &ElGamalSK,
        _source_final_balance: &ElGamalCT,
        _transcript: &mut Transcript,
    ) -> Self {
        // TODO
        WithdrawProof {}
    }

    pub fn verify(&self) -> Result<(), ProofError> {
        Ok(())
    }
}

pub struct TransferProof {}

pub struct TransferFinalizeProof {}
