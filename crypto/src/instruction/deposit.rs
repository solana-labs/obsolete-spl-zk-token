#[cfg(not(target_arch = "bpf"))]
use crate::encryption::elgamal::ElGamal;
use crate::errors::ProofError;

// I think we actually don't need to include the encrypted amount if we use
// pod::add_to_pod_ciphertext since there is no ZK proof involved.
//
pub struct DepositData {
    pub amount: u64, // using u64 for now; add PodU64 to crate::pod?
    pub decimals: u8,
}

impl DepositData {
    #[cfg(not(target_arch = "bpf"))]
    pub fn new(amount: u64, decimals: u8) -> Self {
        DepositData { amount, decimals }
    }
}

pub fn process_deposit(data: DepositData) -> Result<(), ProofError> {
    // ...

    // for demonstration purposes
    let (source_pk, _) = ElGamal::keygen();
    let current_pending_balance = source_pk.encrypt(55_u64).into();

    // 1. check that the instruction data verified correctly

    // 2. add `data.amount` to `current_pending_balance` as syscall
    let _final_pending_balance =
        crate::pod::add_to_pod_ciphertext(current_pending_balance, data.amount)?;

    // 3. store `final_pending_balance` in the destination zk-token account

    // ...

    Ok(())
}
