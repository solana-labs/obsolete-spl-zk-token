#[cfg(not(target_arch = "bpf"))]
use {
    crate::encryption::elgamal::{ElGamalPK, ElGamalSK},
    rand::rngs::OsRng,
};
use {
    crate::{
        encryption::{
            elgamal::ElGamalCT,
            pedersen::{PedersenBase, PedersenOpen},
        },
        errors::ProofError,
        pod::*,
        range_proof::RangeProof,
        transcript::TranscriptProtocol,
    },
    curve25519_dalek::scalar::Scalar,
    merlin::Transcript,
};

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
    pub source_pk: PodElGamalPK, // 32 bytes
    /// The source account available balance *after* the withdraw (encrypted by
    /// `source_pk`)
    pub final_balance_ct: PodElGamalCT, // 64 bytes
    /// Proof that the account is solvent
    pub proof: WithdrawProof,
}

impl WithdrawProofData {
    #[cfg(not(target_arch = "bpf"))]
    pub fn new(
        amount: u64,
        source_pk: ElGamalPK,
        source_sk: &ElGamalSK,
        current_balance: u64,
        current_balance_ct: ElGamalCT,
    ) -> Self {
        // subtract withdraw amount from current balance
        let final_balance = current_balance - amount;

        // encode withdraw amount as an ElGamal ciphertext and subtract it from
        // current source balance
        let amount_encoded = source_pk.encrypt_with(amount, &PedersenOpen::default());
        let final_balance_ct = current_balance_ct - amount_encoded;

        let proof = WithdrawProof::new(source_sk, final_balance, &final_balance_ct);

        Self {
            source_pk: source_pk.into(),
            final_balance_ct: final_balance_ct.into(),
            proof,
        }
    }

    /// Verifies the WithdrawData proof.
    pub fn verify_proof(_amount: u64) -> Result<(), ProofError> {
        // TODO
        Ok(())
    }
}

/// This struct represents the cryptographic proof component that certifies the account's solvency
/// for withdrawal
#[allow(non_snake_case)]
pub struct WithdrawProof {
    /// Wrapper for range proof: R component
    pub R: PodCompressedRistretto,
    /// Wrapper for range proof: z component
    pub z: PodScalar,
    /// Associated range proof
    pub range_proof: RangeProof,
}

#[allow(non_snake_case)]
impl WithdrawProof {
    fn transcript_new() -> Transcript {
        Transcript::new(b"WithdrawProof")
    }

    pub fn new(source_sk: &ElGamalSK, final_balance: u64, final_balance_ct: &ElGamalCT) -> Self {
        let mut transcript = Self::transcript_new();

        // Add a domain separator to record the start of the protocol
        transcript.withdraw_proof_domain_sep();

        // Extract the relevant scalar and Ristretto points from the input
        let H = PedersenBase::default().H;
        let D = final_balance_ct.decrypt_handle.get_point();
        let s = source_sk.get_scalar();

        // Generate wrapper components for range proof
        let r_new = Scalar::random(&mut OsRng);
        let y = Scalar::random(&mut OsRng);
        let R = (y * D + r_new * H).compress();

        transcript.append_point(b"R", &R);
        let c = transcript.challenge_scalar(b"c");

        let z = c * s + y;
        let new_open = PedersenOpen(c * r_new);

        // Generate the range proof component
        let t_1_blinding = PedersenOpen::random(&mut OsRng);
        let t_2_blinding = PedersenOpen::random(&mut OsRng);

        let range_proof = RangeProof::create(
            vec![final_balance],
            vec![64],
            vec![],
            vec![&new_open],
            &t_1_blinding,
            &t_2_blinding,
            &mut transcript,
        );

        WithdrawProof {
            R: R.into(),
            z: z.into(),
            range_proof,
        }
    }

    pub fn verify(&self) -> Result<(), ProofError> {
        Ok(())
    }
}
