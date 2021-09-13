#[cfg(not(target_arch = "bpf"))]
use {
    crate::encryption::pedersen::{Pedersen, PedersenComm, PedersenOpen},
    curve25519_dalek::traits::MultiscalarMul,
    rand::rngs::OsRng,
    subtle::{Choice, ConditionallySelectable},
};
use {
    crate::{
        encryption::pedersen::PedersenBase, errors::ProofError,
        range_proof::generators::BulletproofGens, range_proof::inner_product::InnerProductProof,
        transcript::TranscriptProtocol,
    },
    core::iter,
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{Identity, IsIdentity, VartimeMultiscalarMul},
    },
    merlin::Transcript,
};

pub mod generators;
pub mod inner_product;
pub mod util;

#[allow(non_snake_case)]
pub struct RangeProof {
    pub A: CompressedRistretto,
    pub S: CompressedRistretto,
    pub T_1: CompressedRistretto,
    pub T_2: CompressedRistretto,
    pub t_x: Scalar,
    pub t_x_blinding: Scalar,
    pub e_blinding: Scalar,
    pub ipp_proof: InnerProductProof,
}

#[allow(non_snake_case)]
impl RangeProof {
    #[allow(clippy::many_single_char_names)]
    #[cfg(not(target_arch = "bpf"))]
    pub fn create(
        amounts: Vec<u64>,
        bit_lengths: Vec<usize>,
        _comms: Vec<&PedersenComm>,
        opens: Vec<&PedersenOpen>,
        t_1_blinding: &PedersenOpen,
        t_2_blinding: &PedersenOpen,
        transcript: &mut Transcript,
    ) -> Self {
        let nm = bit_lengths.iter().sum();

        println!("amounts: {:?}\n", amounts);
        println!("bit_lengths: {:?}\n", bit_lengths);

        // Computing the generators online for now. It should ultimately be precomputed.
        let bp_gens = BulletproofGens::new(nm);
        let G = PedersenBase::default().G;
        let H = PedersenBase::default().H;

        // bit-decompose values and commit to the bits
        let a_blinding = Scalar::random(&mut OsRng);
        // let a_blinding = Scalar::zero();
        let mut A = a_blinding * H;

        let mut gens_iter = bp_gens.G(nm).zip(bp_gens.H(nm));
        for (amount_i, m_i) in amounts.iter().zip(bit_lengths.iter()) {
            for j in 0..(*m_i) {
                let (G_ij, H_ij) = gens_iter.next().unwrap();
                let v_ij = Choice::from(((amount_i >> j) & 1) as u8);
                let mut point = -H_ij;
                point.conditional_assign(G_ij, v_ij);
                A += point;
            }
        }

        let G_1: Vec<&RistrettoPoint> = bp_gens.G(1).collect();
        let H_1: Vec<&RistrettoPoint> = bp_gens.H(1).collect();
        let G_1 = G_1[0];
        let H_1 = H_1[0];
        let A_expected = Scalar::one() * G_1 + a_blinding * H;

        println!("A_real: {:?}\n", A.compress());
        println!("A_expected: {:?}\n", A_expected.compress());

        // generate blinding factors and commit as vectors
        // let s_blinding = Scalar::random(&mut OsRng);
        let s_blinding = Scalar::zero();

        let s_L: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
        let s_R: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
        // let s_L: Vec<Scalar> = (0..nm).map(|_| Scalar::zero()).collect();
        // let s_R: Vec<Scalar> = (0..nm).map(|_| Scalar::zero()).collect();

        let S = RistrettoPoint::multiscalar_mul(
            iter::once(&s_blinding).chain(s_L.iter()).chain(s_R.iter()),
            iter::once(&H).chain(bp_gens.G(nm)).chain(bp_gens.H(nm)),
        );

        println!("S: {:?}\n", S.compress());

        transcript.append_point(b"A", &A.compress());
        transcript.append_point(b"S", &S.compress());

        // commit to T1 and T2
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        // let y = Scalar::one();
        // let z = Scalar::one();

        let mut l_poly = util::VecPoly1::zero(nm);
        let mut r_poly = util::VecPoly1::zero(nm);

        let mut i = 0;
        let mut exp_z = z * z;
        for (amount_i, m_i) in amounts.iter().zip(bit_lengths.iter()) {
            let mut exp_y = Scalar::one();
            let mut exp_2 = Scalar::one();

            for j in 0..(*m_i) {
                let a_L_j = Scalar::from((amount_i >> j) & 1);
                let a_R_j = a_L_j - Scalar::one();

                l_poly.0[i] = a_L_j - z;
                l_poly.1[i] = s_L[i];
                r_poly.0[i] = exp_y * (a_R_j + z) + exp_z * exp_2;
                r_poly.1[i] = exp_y * s_R[i];

                println!("l_poly.0: {:?}", l_poly.0[i]);
                println!("l_poly.1: {:?}", l_poly.1[i]);
                println!("r_poly.0: {:?}", r_poly.0[i]);
                println!("r_poly.1: {:?}", r_poly.1[i]);

                exp_y *= y;
                exp_2 = exp_2 + exp_2;
                i += 1;
            }
            exp_z *= z;
        }

        let t_poly = l_poly.inner_product(&r_poly);

        let T_1 = Pedersen::commit_with(t_poly.1, t_1_blinding)
            .get_point()
            .compress();
        let T_2 = Pedersen::commit_with(t_poly.2, t_2_blinding)
            .get_point()
            .compress();

        transcript.append_point(b"T_1", &T_1);
        transcript.append_point(b"T_2", &T_2);

        let x = transcript.challenge_scalar(b"x");

        let mut agg_open = Scalar::zero();
        let mut exp_z = z * z;
        for open in opens {
            agg_open += exp_z * open.get_scalar();
            exp_z *= z;
        }

        let t_blinding_poly = util::Poly2(
            agg_open,
            t_1_blinding.get_scalar(),
            t_2_blinding.get_scalar(),
        );

        // compute t_x
        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);

        let e_blinding = a_blinding + s_blinding * x;
        let l_vec = l_poly.eval(x);
        let r_vec = r_poly.eval(x);

        println!("e_blinding: {:?}\n", e_blinding);
        println!("l_vec: {:?}\n", l_vec);
        println!("r_vec: {:?}\n", r_vec);


        transcript.append_scalar(b"t_x", &t_x);
        transcript.append_scalar(b"t_x_blinding", &t_x_blinding);
        transcript.append_scalar(b"e_blinding", &e_blinding);

        let w = transcript.challenge_scalar(b"w");
        let Q = w * G;

        let _c = transcript.challenge_scalar(b"c");

        let G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(nm).collect();
        let H_factors: Vec<Scalar> = util::exp_iter(y.invert()).take(nm).collect();

        println!("G_factors: {:?}\n", G_factors);
        println!("H_factors: {:?}\n", H_factors);

        // ------------------------------------------------------------------------

        let l_vec_alt = l_vec.iter().cloned();
        let r_vec_alt = r_vec.iter().zip(H_factors.iter()).map(|(r, h)| r * h);
        let prod = util::inner_product(&l_vec, &r_vec);

        println!("prod: {:?}\n", prod);

        let P = RistrettoPoint::multiscalar_mul(
            l_vec_alt.chain(r_vec_alt)
            ,
            bp_gens.G(nm).chain(bp_gens.H(nm))
            ,
        );

        let P_with_product = P + prod * Q;

        println!("\nP prover: {:?}\n", P.compress());
        println!("\nP_with_product: {:?}\n", P_with_product.compress());


        println!("{:?}\n", (-Scalar::one() * G_1 + Scalar::from(6u64) * H_1 - Scalar::from(6u64) * Q).compress());
        // println!("{:?}\n", (Scalar::from(1u64) * H_1).compress());


        let minus_z_vec = (0..nm).map(|_| -z);

        let concat_z_and_2 = util::exp_iter(Scalar::from(2u64)).take(1).map(|exp_2| exp_2 * z*z);
        let concat_z_2_y = concat_z_and_2.zip(util::exp_iter(y.invert())).map(|(x, y)| x * y);
        let concat_z_2_y_add_z = concat_z_2_y.map(|x| x + z);

        // let P_alt = RistrettoPoint::multiscalar_mul(
        //     iter::once(Scalar::one())
        //         .chain(iter::once(x))
        //         .chain(iter::once(-e_blinding))
        //         .chain(minus_z_vec)
        //         .chain(concat_z_2_y_add_z)
        //     ,
        //     iter::once(A)
        //         .chain(iter::once(S))
        //         .chain(iter::once(H))
        //         .chain(bp_gens.G(nm).map(|&x| x))
        //         .chain(bp_gens.H(nm).map(|&x| x))
        //     ,
        // );

        // println!("\nP_alt: {:?}\n", P_alt.compress());



        // ------------------------------------------------------------------------

        println!("{:?}", G_factors.len());

        let ipp_proof = InnerProductProof::create(
            &Q,
            &G_factors,
            &H_factors,
            bp_gens.G(nm).cloned().collect(),
            bp_gens.H(nm).cloned().collect(),
            l_vec,
            r_vec,
            transcript,
        );

        // println!("ipp.L_vec: {:?}", ipp_proof.L_vec);
        // println!("ipp.R_vec: {:?}", ipp_proof.R_vec);
        // println!("ipp.a: {:?}", ipp_proof.a);
        // println!("ipp.b: {:?}", ipp_proof.b);


        // -----------------------------------------------------------------------

        // let Gs: Vec<RistrettoPoint> = bp_gens.G(nm).cloned().collect();
        // let Hs: Vec<RistrettoPoint> = bp_gens.H(nm).cloned().collect();

        // let result = ipp_proof.verify(
        //     32,
        //     &G_factors,
        //     &H_factors,
        //     &P_with_product,
        //     &Q,
        //     &Gs,
        //     &Hs,
        //     &mut transcript_verifier,
        // ).is_ok();

        // println!("result: {:?}", result);



        // -----------------------------------------------------------------------


        RangeProof {
            A: A.compress(),
            S: S.compress(),
            T_1,
            T_2,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        }
    }

    #[allow(clippy::many_single_char_names)]
    pub fn verify(
        &self,
        comms: Vec<&CompressedRistretto>,
        n: usize,
        m: usize,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        // TODO: clean-up variables

        let G = PedersenBase::default().G;
        let H = PedersenBase::default().H;

        let nm = n * m;
        let bp_gens = BulletproofGens::new(nm);

        // if !(n == 8 || n == 16 || n == 32 || n == 64 || n == 128) {
        //     return Err(ProofError::InvalidBitsize);
        // }

        // transcript.validate_and_append_point(b"A", &self.A)?;
        // transcript.validate_and_append_point(b"S", &self.S)?;
        transcript.append_point(b"A", &self.A);
        transcript.append_point(b"S", &self.S);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        let zz = z * z;
        let minus_z = -z;

        // transcript.validate_and_append_point(b"T_1", &self.T_1)?;
        // transcript.validate_and_append_point(b"T_2", &self.T_2)?;
        transcript.append_point(b"T_1", &self.T_1);
        transcript.append_point(b"T_2", &self.T_2);

        let x = transcript.challenge_scalar(b"x");

        transcript.append_scalar(b"t_x", &self.t_x);
        transcript.append_scalar(b"t_x_blinding", &self.t_x_blinding);
        transcript.append_scalar(b"e_blinding", &self.e_blinding);

        let w = transcript.challenge_scalar(b"w");

        // Challenge value for batching statements to be verified
        let c = transcript.challenge_scalar(b"c");

        println!("w verify: {:?}", w);
        println!("c verify: {:?}", c);

        let (x_sq, x_inv_sq, s) = self.ipp_proof.verification_scalars(n * m, transcript)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;



        // ------------------------- P Verification ------------------------------------------------

        // Construct concat_z_and_2, an iterator of the values of
        // z^0 * \vec(2)^n || z^1 * \vec(2)^n || ... || z^(m-1) * \vec(2)^n
        let powers_of_2: Vec<Scalar> = util::exp_iter(Scalar::from(2u64)).take(n).collect();
        let concat_z_and_2: Vec<Scalar> = util::exp_iter(z)
            .take(m)
            .flat_map(|exp_z| powers_of_2.iter().map(move |exp_2| exp_2 * exp_z))
            .collect();

        let g_alt = s.iter().map(|s_i| minus_z);
        let h_alt = s_inv.clone()
            .zip(util::exp_iter(y.invert()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2));

        let P_alt = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(x))
                .chain(iter::once(-self.e_blinding))
                .chain(g_alt)
                .chain(h_alt)
            ,
            iter::once(self.A.decompress())
                .chain(iter::once(self.S.decompress()))
                .chain(iter::once(Some(H)))
                .chain(bp_gens.G(nm).map(|&x| Some(x)))
                .chain(bp_gens.H(nm).map(|&x| Some(x)))
            ,
        )
        .ok_or_else(|| ProofError::VerificationError)?;

        println!("P_alt verify: {:?}\n", P_alt.compress());

        // -------------------------- Inner Product Verification ------------------------------------

        let g_ip = s.iter().map(|s_i| - a * s_i);
        let h_ip = s_inv
            .zip(util::exp_iter(y.invert()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| exp_y_inv * (- b * s_i_inv));

        let basepoint_scalar_ip = w * (self.t_x - a * b);

        let P_ip = RistrettoPoint::optional_multiscalar_mul(
            iter::once(basepoint_scalar_ip)
                .chain(x_sq.iter().cloned())
                .chain(x_inv_sq.iter().cloned())
                .chain(g_ip)
                .chain(h_ip)
            ,
            iter::once(Some(G))
                .chain(self.ipp_proof.L_vec.iter().map(|L| L.decompress()))
                .chain(self.ipp_proof.R_vec.iter().map(|R| R.decompress()))
                .chain(bp_gens.G(nm).map(|&x| Some(x)))
                .chain(bp_gens.H(nm).map(|&x| Some(x)))
            ,
        )
        .ok_or_else(|| ProofError::VerificationError)?;

        println!("P_ip verify: {:?}\n", (-P_ip).compress());



        // ------------------------------ Polynomial Verification ----------------------------------

        let value_commitment_scalars = util::exp_iter(z).take(m).map(|z_exp| c * zz * z_exp);
        let basepoint_scalar = c * (delta(n, m, &y, &z) - self.t_x);

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(c * x))
                .chain(iter::once(c * x * x))
                .chain(iter::once(-c * self.t_x_blinding))
                .chain(iter::once(basepoint_scalar))
                .chain(value_commitment_scalars),
            iter::once(Some(RistrettoPoint::identity()))
                .chain(iter::once(self.T_1.decompress()))
                .chain(iter::once(self.T_2.decompress()))
                .chain(iter::once(Some(H)))
                .chain(iter::once(Some(G)))
                .chain(comms.iter().map(|V| V.decompress())),
        )
        .ok_or(ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

/// Compute
/// \\[
/// \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
/// \\]
fn delta(n: usize, m: usize, y: &Scalar, z: &Scalar) -> Scalar {
    let sum_y = util::sum_of_powers(y, n * m);
    let sum_2 = util::sum_of_powers(&Scalar::from(2u64), n);
    let sum_z = util::sum_of_powers(z, m);

    (z - z * z) * sum_y - z * z * z * sum_2 * sum_z
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_rangeproof() {
        let (comm, open) = Pedersen::commit(1 as u64);

        let t_1_blinding = PedersenOpen::random(&mut OsRng);
        let t_2_blinding = PedersenOpen::random(&mut OsRng);

        let mut transcript_create = Transcript::new(b"Test");
        let mut transcript_verify = Transcript::new(b"Test");

        let proof = RangeProof::create(
            vec![1],
            vec![32 as usize],
            vec![&comm],
            vec![&open],
            &t_1_blinding,
            &t_2_blinding,
            &mut transcript_create,
        );

        assert!(proof.verify(vec![&comm.get_point().compress()], 32, 1, &mut transcript_verify).is_ok());
    }
}
