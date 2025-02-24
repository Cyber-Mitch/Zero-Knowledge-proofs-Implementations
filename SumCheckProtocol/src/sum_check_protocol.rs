use ark_ff::{field_hashers::HashToField, Field};
use ark_poly::univariate;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

/// Error type for the Fiat–Shamir transformation.
#[derive(Debug, thiserror::Error)]
pub enum FSSError {
    /// An error during serialization.
    #[error("Serialization codec error")]
    Serialization,
}

impl From<SerializationError> for FSSError {
    fn from(_: SerializationError) -> Self {
        FSSError::Serialization
    }
}

/// Result alias for Fiat–Shamir functions.
pub type FSResult<T> = std::result::Result<T, FSSError>;

/// A minimal RNG trait for field elements.
pub trait FieldRng<F: Field> {
    /// Draw a field element.
    fn draw(&mut self) -> F;
}

/// Trait for an interactive prover in the Fiat–Shamir transformation.
pub trait FSProverInterface<F: Field> {
    /// Return the initial prover message (g₁) as a byte vector.
    fn get_initial_message(&mut self) -> FSResult<Vec<u8>>;

    /// Execute the prover’s round with the given challenge and return the round message.
    fn perform_round(&mut self, round_index: usize, challenge: F) -> FSResult<Vec<u8>>;

    /// Return the total number of rounds.
    fn rounds_count(&self) -> usize;
}

/// A transcript for the Fiat–Shamir transformation.
pub struct FSTranscript {
    pub messages: Vec<Vec<u8>>,
}

/// Generate a Fiat–Shamir transcript from an interactive prover,
/// thereby converting it into a non–interactive transcript.
pub fn create_fs_transcript<F: Field, P: FSProverInterface<F>, H: HashToField<F>>(
    mut prover: P,
) -> FSResult<FSTranscript> {
    let hasher = H::new(&[]);
    let initial_msg = prover.get_initial_message()?;
    let mut hash_buffer = initial_msg.clone();
    let mut transcript_msgs = vec![initial_msg];

    for round in 1..prover.rounds_count() {
        let challenge = hasher.hash_to_field(&hash_buffer, 1)[0];
        let round_msg = prover.perform_round(round, challenge)?;
        hash_buffer.extend_from_slice(&round_msg);
        transcript_msgs.push(round_msg);
    }

    Ok(FSTranscript {
        messages: transcript_msgs,
    })
}

/// A helper RNG that returns fixed field elements from a predetermined list.
pub struct FixedRandom<F> {
    values: Vec<F>,
    index: usize,
}

impl<F: Field> FixedRandom<F> {
    /// Create a new FixedRandom instance from a list of field elements.
    pub fn new(values: Vec<F>) -> Self {
        Self { values, index: 0 }
    }
}

impl<F: Field + Copy> FieldRng<F> for FixedRandom<F> {
    fn draw(&mut self) -> F {
        let value = self.values[self.index];
        self.index += 1;
        value
    }
}

/// Trait for an interactive verifier in the Fiat–Shamir transformation.
pub trait FSVerifierInterface<F: Field, R: FieldRng<F>> {
    /// Execute a verification round using the provided round message and RNG.
    fn execute_round(&mut self, round_index: usize, msg: &[u8], rng: &mut R) -> FSResult<bool>;
}

/// Verify a Fiat–Shamir transcript by converting an interactive verifier
/// into a non–interactive one.
pub fn verify_fs_transcript<F: Field, V: FSVerifierInterface<F, FixedRandom<F>>, H: HashToField<F>>(
    transcript: FSTranscript,
    mut verifier: V,
) -> FSResult<bool> {
    let hasher = H::new(&[]);
    let mut hash_buffer = Vec::new();

    for (round, msg) in transcript.messages.iter().enumerate() {
        hash_buffer.extend_from_slice(msg);
        let challenge = hasher.hash_to_field(&hash_buffer, 1)[0];
        // Use FixedRandom to supply the challenge.
        if !verifier.execute_round(round, msg, &mut FixedRandom::new(vec![challenge]))? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// --- Sum–Check Prover for a Multivariate Polynomial Claim ---
/// (This is the interactive prover used in the sum–check protocol.)

use ark_bls12_381::Fr as ScalarField;
use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm};
use ark_poly::polynomial::univariate::SparsePolynomial as UniSparsePolynomial;
use ark_poly::MVPolynomial;
use ark_std::cfg_into_iter;
use rand::Rng;

pub type MultiPoly = SparsePolynomial<ScalarField, SparseTerm>;
pub type UniPoly = UniSparsePolynomial<ScalarField>;

/// Converts an index into a binary vector of field elements of length `n`.
pub fn n_to_vec(i: usize, n: usize) -> Vec<ScalarField> {
    format!("{:0>width$}", format!("{:b}", i), width = n)
        .chars()
        .map(|x| if x == '1' { ScalarField::one() } else { ScalarField::zero() })
        .collect()
}

/// Simulates the memory of a single interactive prover instance.
#[derive(Debug, Clone)]
pub struct Prover {
    pub g: MultiPoly,
    pub r_vec: Vec<ScalarField>,
}

impl Prover {
    /// Create a new Prover from the given multivariate polynomial.
    pub fn new(g: &MultiPoly) -> Self {
        Prover {
            g: g.clone(),
            r_vec: vec![],
        }
    }

    /// Given the polynomial g, fix the next variable (if provided) and generate a univariate polynomial.
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

    /// Evaluate g over a permutation of points and sum all contributions into one univariate polynomial.
    pub fn evaluate_gj(&self, points: Vec<ScalarField>) -> UniPoly {
        cfg_into_iter!(self.g.terms()).fold(
            UniPoly::from_coefficients_vec(vec![]),
            |sum, (coeff, term)| {
                let (coeff_eval, fixed_term) = self.evaluate_term(&term, &points);
                let curr = match fixed_term {
                    None => UniPoly::from_coefficients_vec(vec![(0, *coeff * coeff_eval)]),
                    Some(t) => UniPoly::from_coefficients_vec(vec![(
                        t.degree(),
                        *coeff * coeff_eval,
                    )]),
                };
                curr + sum
            },
        )
    }

    /// Evaluate a term with a fixed univariate assignment, returning the accumulated coefficient and any remaining term.
    pub fn evaluate_term(
        &self,
        term: &SparseTerm,
        point: &Vec<ScalarField>,
    ) -> (ScalarField, Option<SparseTerm>) {
        let mut fixed_term: Option<SparseTerm> = None;
        let coeff: ScalarField =
            cfg_into_iter!(term).fold(ScalarField::one(), |prod, (var, power)| match *var {
                j if j == self.r_vec.len() => {
                    fixed_term = Some(SparseTerm::new(vec![(j, *power)]));
                    prod
                }
                j if j < self.r_vec.len() => self.r_vec[j].pow(&[*power as u64]) * prod,
                _ => point[*var - self.r_vec.len()].pow(&[*power as u64]) * prod,
            });
        (coeff, fixed_term)
    }

    /// Compute the sum of evaluations of g over the entire boolean hypercube.
    pub fn slow_sum_g(&self) -> ScalarField {
        let v = self.g.num_vars();
        let n = 2u32.pow(v as u32);
        (0..n)
            .map(|n| self.g.evaluate(&n_to_vec(n as usize, v)))
            .sum()
    }
}

/// Implement the FSProverInterface for our interactive Prover.
impl FSProverInterface<ScalarField> for Prover {
    fn get_initial_message(&mut self) -> FSResult<Vec<u8>> {
        let uni_poly = self.gen_uni_polynomial(None);
        let mut buf = Vec::new();
        uni_poly.serialize_uncompressed(&mut buf)?;
        Ok(buf)
    }

    fn perform_round(&mut self, _round_index: usize, challenge: ScalarField) -> FSResult<Vec<u8>> {
        let uni_poly = self.gen_uni_polynomial(Some(challenge));
        let mut buf = Vec::new();
        uni_poly.serialize_uncompressed(&mut buf)?;
        Ok(buf)
    }

    fn rounds_count(&self) -> usize {
        self.g.num_vars()
    }
}

/// A helper function that returns a random challenge.
pub fn get_r() -> Option<ScalarField> {
    let mut rng = rand::thread_rng();
    Some(rng.gen())
}

/// Build a degree lookup table for all variables in g.
pub fn max_degrees(g: &MultiPoly) -> Vec<usize> {
    let mut lookup: Vec<usize> = vec![0; g.num_vars()];
    cfg_into_iter!(g.terms()).for_each(|(_, term)| {
        cfg_into_iter!(term).for_each(|(var, power)| {
            if *power > lookup[*var] {
                lookup[*var] = *power
            }
        });
    });
    lookup
}

/// Interactive verification of the prover's claim.
/// (This function uses assertions to ensure consistency.)
pub fn verify(g: &MultiPoly, c_1: ScalarField) -> bool {
    // 1st round
    let mut p = Prover::new(g);
    let mut gi = p.gen_uni_polynomial(None);
    let mut expected_c = gi.evaluate(&ScalarField::zero()) + gi.evaluate(&ScalarField::one());
    assert_eq!(c_1, expected_c);
    let lookup_degree = max_degrees(g);
    assert!(gi.degree() <= lookup_degree[0]);

    // Middle rounds
    for j in 1..p.g.num_vars() {
        let r = get_r();
        expected_c = gi.evaluate(&r.unwrap());
        gi = p.gen_uni_polynomial(r);
        let new_c = gi.evaluate(&ScalarField::zero()) + gi.evaluate(&ScalarField::one());
        assert_eq!(expected_c, new_c);
        assert!(gi.degree() <= lookup_degree[j]);
    }
    // Final round
    let r = get_r();
    expected_c = gi.evaluate(&r.unwrap());
    p.r_vec.push(r.unwrap());
    let new_c = p.g.evaluate(&p.r_vec);
    assert_eq!(expected_c, new_c);
    true
}

/// Brute-force verification by summing over all assignments.
pub fn slow_verify(g: &MultiPoly, c_1: ScalarField) -> bool {
    let p = Prover::new(g);
    p.slow_sum_g() == c_1
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as ScalarField;
    use ark_ff::Field;
    use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm};
    use ark_poly::polynomial::univariate::SparsePolynomial as UniSparsePolynomial;
    use sum_check_protocol::DefaultFieldHasher;
    use ark_serialize::CanonicalSerialize;

    /// Construct a simple polynomial for testing.
    /// For example, g(x, y) = 1*x + 2*y + 3.
    fn simple_poly() -> MultiPoly {
        let terms = vec![
            (ScalarField::from(1u32), SparseTerm::new(vec![(0, 1)])), // x
            (ScalarField::from(2u32), SparseTerm::new(vec![(1, 1)])), // 2*y
            (ScalarField::from(3u32), SparseTerm::new(vec![])),        // constant
        ];
        SparsePolynomial::from_coefficients_slice(2, &terms)
    }

    /// Dummy FS verifier for the sum–check FS transformation.
    struct DummySumcheckFSVerifier;
    impl FSVerifierInterface<ScalarField, FixedRandom<ScalarField>> for DummySumcheckFSVerifier {
        fn execute_round(
            &mut self,
            _round_index: usize,
            msg: &[u8],
            _rng: &mut FixedRandom<ScalarField>,
        ) -> FSResult<bool> {
            // In our dummy verifier, simply check that the round message is non–empty.
            Ok(!msg.is_empty())
        }
    }

    #[test]
    fn test_sumcheck_fs_transcript() {
        let poly = simple_poly();
        // For testing, we compute the claim as the brute-force sum.
        let claim = {
            let prover = Prover::new(&poly);
            prover.slow_sum_g()
        };

        // Verify that the interactive verification passes.
        assert!(verify(&poly, claim));
        assert!(slow_verify(&poly, claim));

        // Now, use our FS transformation.
        let mut interactive_prover = Prover::new(&poly);
        let transcript = create_fs_transcript::<ScalarField, _, DefaultFieldHasher<_>>(
            &mut interactive_prover,
        )
        .expect("Failed to create FS transcript");

        // Use the dummy FS verifier.
        let verifier = DummySumcheckFSVerifier;

        let valid = verify_fs_transcript::<ScalarField, _, DefaultFieldHasher<_>>(
            transcript,
            verifier,
        )
        .expect("FS transcript verification failed");

        assert!(valid, "The FS transcript should verify as valid");
    }
}
