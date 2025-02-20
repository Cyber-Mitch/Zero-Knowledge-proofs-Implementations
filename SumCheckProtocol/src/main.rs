
// Declare modules so that the compiler includes their code.
mod fiat_shamir_for_sumcheck;
mod sum_check_protocol;

use ark_poly::MVPolynomial;
use ark_poly::multivariate::Term;
use ark_bls12_381::Fr as ScalarField;
use ark_ff::One; // For ScalarField::one()
use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm};

fn main() {
   

    // Step 1: Construct the polynomial g(x₁, x₂) = 1 + x₁ + x₂.
    let mut terms = Vec::new();
    // Constant term: 1.
    terms.push((ScalarField::one(), SparseTerm::new(vec![])));
    // x₁ term: 1 * x₁.
    terms.push((ScalarField::one(), SparseTerm::new(vec![(0, 1)])));
    // x₂ term: 1 * x₂.
    terms.push((ScalarField::one(), SparseTerm::new(vec![(1, 1)])));

    // Create the multivariate polynomial from the terms.
    let g: sum_check_protocol::MultiPoly = SparsePolynomial::from_coefficients_vec(2, terms);

    // Step 2: Define the claimed sum c₁.
    // For g(x₁, x₂) = 1 + x₁ + x₂, the sum over {0,1}² is 8.
    let c1 = ScalarField::from(8u32);

    // Step 3: Call the non‑interactive verification procedure.
    // The verify_non_interactive function uses the imported Fiat–Shamir transcript to
    // derive challenges deterministically, making the protocol non‑interactive.
    let valid = sum_check_protocol::verify_non_interactive(&g, c1);

    // Step 4: Print the verification result.
    println!("Verification result: {}", valid);
}
