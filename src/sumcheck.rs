extern crate rand;
extern crate sha2;

use rand::Rng;
use sha2::{Sha256, Digest};

// Define a simple polynomial structure
struct Polynomial {
    coefficients: Vec<i64>,
}

impl Polynomial {
    fn new(coefficients: Vec<i64>) -> Self {
        Polynomial { coefficients }
    }

    fn evaluate(&self, x: i64) -> i64 {
        self.coefficients.iter().rev().fold(0, |acc, &c| acc * x + c)
    }
}

// Prover structure
struct Prover {
    polynomial: Polynomial,
}

impl Prover {
    fn new(polynomial: Polynomial) -> Self {
        Prover { polynomial }
    }

    fn commit(&self) -> (i64, i64) {
        let r = rand::thread_rng().gen_range(0..100);
        let evaluation = self.polynomial.evaluate(r);
        (r, evaluation)
    }

    fn respond(&self, challenge: i64) -> i64 {
        self.polynomial.evaluate(challenge)
    }
}

// Verifier structure
struct Verifier;

impl Verifier {
    fn verify(commitment: (i64, i64), challenge: i64, response: i64) -> bool {
        let (r, evaluation) = commitment;
        evaluation == response
    }
}

// Fiat-Shamir transformation for sum-check
fn fiat_shamir_sum_check(prover: &Prover) -> ((i64, i64), i64, i64) {
    let commitment = prover.commit();
    let challenge = generate_challenge(&commitment);
    let response = prover.respond(challenge);
    (commitment, challenge, response)
}

fn generate_challenge(commitment: &(i64, i64)) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", commitment));
    let result = hasher.finalize();
    i64::from_le_bytes(result[..8].try_into().expect("Slice with incorrect length"))
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_evaluation() {
        let coefficients = vec![1, 2, 3, 4];
        let polynomial = Polynomial::new(coefficients);
        assert_eq!(polynomial.evaluate(2), 27); // 1 + 2*2 + 3*2^2 + 4*2^3 = 27
    }

    #[test]
    fn test_fiat_shamir_sum_check() {
        let coefficients = vec![1, 2, 3, 4];
        let polynomial = Polynomial::new(coefficients);
        let prover = Prover::new(polynomial);

        let (commitment, challenge, response) = fiat_shamir_sum_check(&prover);
        let is_valid = Verifier::verify(commitment, challenge, response);

        assert!(is_valid);
    }

    #[test]
    fn test_generate_challenge() {
        let commitment = (10, 20);
        let challenge = generate_challenge(&commitment);
        assert_ne!(challenge, 0); // Challenge should not be zero
    }
}