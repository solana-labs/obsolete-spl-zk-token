use crate::errors::ProofError;
use crate::pod::*;
use zeroable::Zeroable;

// An ElGamal ciphertext is of the form
//   ElGamalCT {
//     msg_comm: r * H + x * G
//     decrypt_handle: r * P
//   }
//
// where
// - G, H: constants for the system (RistrettoPoint)
// - P: ElGamal public key component (RistrettoPoint)
// - r: encryption randomness (Scalar)
// - x: message (Scalar)
//
// Upon receiving a `CreateAccount` instruction, the ZK-Token program should encrypt x=0 (i.e.
// Scalar::zero()) and store it as `pending_balance` and `spendable_balance`.
//
// For regular encryption, it is important that r is generated from a proper randomness source. But
// for the `CreateAccount` instruction, it is already known that x is always 0. So r can just be
// set Scalar::zero().
//
// This means that the ElGamalCT should simply be
//   ElGamalCT {
//     msg_comm: 0 * H + 0 * G = 0
//     decrypt_handle: 0 * P = 0
//   }
//
// This should just be encoded as [0; 64]

pub struct CreateAccountData {
    /// The public key associated with the account
    pub elgamal_pk: PodElGamalPK,
}

pub fn process_create_account(data: CreateAccountData) -> Result<(), ProofError> {
    // 1. instantiate public key for the account
    let _elgamal_pk = data.elgamal_pk;

    // 2. instantiate new pending and spendable balance for the account
    let _new_pending_balance = PodElGamalCT::zeroed();
    let _new_spendable_balance = PodElGamalCT::zeroed();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::elgamal::{ElGamal, ElGamalCT};
    use crate::encryption::pedersen::PedersenOpen;
    use rand::rngs::OsRng;
    use std::convert::TryInto;

    #[test]
    fn test_zero_ct() {
        let spendable_balance = PodElGamalCT::zeroed();
        let spendable_ct: ElGamalCT = spendable_balance.try_into().unwrap();

        // spendable_ct should be an encryption of 0 for any public key when
        // `PedersenOpen::default()` is used
        let (pk, _) = ElGamal::keygen();
        let balance: u64 = 0;
        assert_eq!(
            spendable_ct,
            pk.encrypt_with(balance, &PedersenOpen::default())
        );

        // homomorphism should work like any other ciphertext
        let open = PedersenOpen::random(&mut OsRng);
        let transfer_amount_ct = pk.encrypt_with(55_u64, &open);
        let transfer_amount_pod: PodElGamalCT = transfer_amount_ct.into();

        let sum = crate::pod::add_pod_ciphertexts(spendable_balance, transfer_amount_pod).unwrap();

        let expected: PodElGamalCT = pk.encrypt_with(55_u64, &open).into();
        assert_eq!(expected, sum);
    }
}
