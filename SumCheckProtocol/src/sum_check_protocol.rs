use crate::fiat_shamir_for_sumcheck::Transcript;
use ark_bls12_381::Fr as ScalarField;
use ark_ff::PrimeField; // for from_le_bytes_mod_order
use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm};
use ark_poly::polynomial::univariate::SparsePolynomial as UniSparsePolynomial;
use ark_poly::polynomial::{MVPolynomial, Polynomial};
use ark_std::cfg_into_iter;
use ark_poly::multivariate::Term;
use ark_ff::Field;
use ark_ff::BigInteger;

pub type MultiPoly = SparsePolynomial<ScalarField, SparseTerm>;
pub type UniPoly = UniSparsePolynomial<ScalarField>;

/// Converts an integer into a vector of field elements representing a binary string of length n.
/// This is used for evaluating polynomials over the Boolean hypercube.
pub fn n_to_vec(i: usize, n: usize) -> Vec<ScalarField> {
    format!("{:0>width$}", format!("{:b}", i), width = n)
        .chars()
        .map(|x| if x == '1' { 1.into() } else { 0.into() })
        .collect()
}

/// Simulates the prover’s state.
#[derive(Debug, Clone)]
pub struct Prover {
    pub g: MultiPoly,
    pub r_vec: Vec<ScalarField>,
}

impl Prover {
    pub fn new(g: &MultiPoly) -> Self {
        Prover {
            g: g.clone(),
            r_vec: vec![],
        }
    }

    /// Given a challenge (optional), generates a univariate polynomial by “fixing” one variable.
    pub fn gen_uni_polynomial(&mut self, r: Option<ScalarField>) -> UniPoly {
        if let Some(val) = r {
            self.r_vec.push(val);
        }
        let v = self.g.num_vars() - self.r_vec.len();
        (0..(2u32.pow(v as u32 - 1))).fold(
            UniPoly::from_coefficients_vec(vec![(0, 0u32.into())]),
            |sum, n| sum + self.evaluate_gj(n_to_vec(n as usize, v)),
        )
    }

    /// Evaluates the polynomial with some variables fixed, yielding a univariate polynomial.
    pub fn evaluate_gj(&self, points: Vec<ScalarField>) -> UniPoly {
        cfg_into_iter!(self.g.terms()).fold(
            UniPoly::from_coefficients_vec(vec![]),
            |sum, (coeff, term)| {
                let (coeff_eval, fixed_term) = self.evaluate_term(&term, &points);
                let curr = match fixed_term {
                    None => UniPoly::from_coefficients_vec(vec![(0, *coeff * coeff_eval)]),
                    Some(ref ft) => UniPoly::from_coefficients_vec(vec![(
                        ft.degree(),
                        *coeff * coeff_eval,
                    )]),
                };
                curr + sum
            },
        )
    }

    /// Evaluates a term from the polynomial with fixed variables.
    pub fn evaluate_term(
        &self,
        term: &SparseTerm,
        point: &Vec<ScalarField>,
    ) -> (ScalarField, Option<SparseTerm>) {
        let mut fixed_term: Option<SparseTerm> = None;
        let coeff: ScalarField = cfg_into_iter!(term).fold(1u32.into(), |product, (var, power)| {
            match *var {
                j if j == self.r_vec.len() => {
                    fixed_term = Some(SparseTerm::new(vec![(j, *power)]));
                    product
                }
                j if j < self.r_vec.len() => self.r_vec[j].pow(&[*power as u64]) * product,
                _ => point[*var - self.r_vec.len()].pow(&[*power as u64]) * product,
            }
        });
        (coeff, fixed_term)
    }

    /// Computes the sum of g over the Boolean hypercube.
    pub fn slow_sum_g(&self) -> ScalarField {
        let v = self.g.num_vars();
        let n = 2u32.pow(v as u32);
        (0..n)
            .map(|n| self.g.evaluate(&n_to_vec(n as usize, v)))
            .sum()
    }
}

/// Computes a lookup table of the maximum degree for each variable in g.
pub fn max_degrees(g: &MultiPoly) -> Vec<usize> {
    let mut lookup: Vec<usize> = vec![0; g.num_vars()];
    cfg_into_iter!(g.terms()).for_each(|(_, term)| {
        cfg_into_iter!(term).for_each(|(var, power)| {
            if *power > lookup[*var] {
                lookup[*var] = *power;
            }
        });
    });
    lookup
}

/// Non‑interactive verification using the Fiat–Shamir transcript.
/// Instead of drawing random challenges, the verifier derives them deterministically.
pub fn verify_non_interactive(g: &MultiPoly, c_1: ScalarField) -> bool {
    // Initialize the transcript.
    let mut transcript = Transcript::new();
    let mut p = Prover::new(g);

    // === Round 1: Generate the first univariate polynomial and append its serialization.
    let mut gi = p.gen_uni_polynomial(None);
    transcript.append_message(&serialize_poly(&gi));

    // Verifier: Check that the claimed sum c₁ equals gi(0) + gi(1).
    let mut expected_c = gi.evaluate(&0u32.into()) + gi.evaluate(&1u32.into());
    assert_eq!(c_1, expected_c);
    let lookup_degree = max_degrees(g);
    assert!(gi.degree() <= lookup_degree[0]);

    // === Middle Rounds: For each remaining variable, derive a challenge from the transcript.
    for _ in 1..p.g.num_vars() {
        let challenge_bytes = transcript.get_challenge();
        let r = ScalarField::from_le_bytes_mod_order(&challenge_bytes);
        transcript.append_message(&r.into_repr().to_bytes_le());

        expected_c = gi.evaluate(&r);
        gi = p.gen_uni_polynomial(Some(r));
        transcript.append_message(&serialize_poly(&gi));

        let new_c = gi.evaluate(&0u32.into()) + gi.evaluate(&1u32.into());
        assert_eq!(expected_c, new_c);
    }

    // === Final Round: Derive final challenge, update transcript, and verify final evaluation.
    let challenge_bytes = transcript.get_challenge();
    let r = ScalarField::from_le_bytes_mod_order(&challenge_bytes);
    expected_c = gi.evaluate(&r);
    transcript.append_message(&r.into_repr().to_bytes_be());
    p.r_vec.push(r);
    let new_c = p.g.evaluate(&p.r_vec);
    assert_eq!(expected_c, new_c);

    true
}

/// A slower verification that sums g over the entire hypercube directly.
pub fn slow_verify(g: &MultiPoly, c_1: ScalarField) -> bool {
    let p = Prover::new(g);
    let manual_sum = p.slow_sum_g();
    manual_sum == c_1
}

/// A simple serialization for a univariate polynomial.
/// In a production system, use a canonical serialization.
fn serialize_poly(poly: &UniPoly) -> Vec<u8> {
    format!("{:?}", poly).into_bytes()
}
