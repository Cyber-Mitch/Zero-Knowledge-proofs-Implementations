use std::iter;

use ark_ff::{FftField, Field, Zero};
use ark_poly::{
    univariate, DenseMultilinearExtension, DenseUVPolynomial, MultilinearExtension, Polynomial,
};
use ark_std::rand::Rng;

use sum_check_protocol::{
    Prover as ScProver, Verifier as ScVerifier, VerifierRoundResult as ScVerifierRoundResult,
};

mod circuit;
mod round_polynomial;

use round_polynomial::W;
use circuit::{Circuit, CircuitEvaluation};

/// GKR protocol error type.
#[derive(Debug, thiserror::Error)]
pub enum GkrError {
    /// The verifier is in an unexpected state.
    #[error("Verifier is in the wrong state.")]
    InvalidVerifierState,
}

/// GKR protocol result type.
pub type GkrResult<T> = std::result::Result<T, GkrError>;

/// The state of the verifier.
pub struct GkrVerifier<F: FftField> {
    /// Challenge vectors: \( r_0, r_1, \dots, r_n \).
    challenge_history: Vec<Vec<F>>,
    /// Accumulated output values.
    output_accum: Vec<F>,
    /// The circuit under verification.
    circuit: Circuit,
    /// Internal state of the verifier.
    inner_state: VerifierInnerState<F>,
}

/// The internal state of the verifier.
enum VerifierInnerState<F: FftField> {
    Idle,
    InSumCheck {
        /// Combined randomness from the sum-check: \( b \) and \( c \).
        combined_rand: Vec<F>,
        /// Sum-check verifier instance.
        sc_verifier: Box<ScVerifier<F, W<F>>>,
        /// Addition gate polynomial.
        add_poly: DenseMultilinearExtension<F>,
        /// Multiplication gate polynomial.
        mul_poly: DenseMultilinearExtension<F>,
    },
}

impl<F: FftField> GkrVerifier<F> {
    /// Initialize a new `GkrVerifier` using the given circuit.
    ///
    /// At the start, a random point \( r_0 \) is chosen and 
    /// \( m_0 \leftarrow \tilde{D}(r_0) \) is computed.
    pub fn new(circ: Circuit) -> Self {
        Self {
            challenge_history: vec![],
            output_accum: vec![],
            circuit: circ,
            inner_state: VerifierInnerState::Idle,
        }
    }

    #[inline]
    fn begin_round(
        &mut self,
        init_challenge: F,
        round_index: usize,
        var_count: usize,
    ) -> GkrResult<VerifierResponse<F>> {
        let last_challenge = self
            .challenge_history
            .last()
            .expect("Missing initial challenge vector");
        let add_poly_ext = self.circuit.add_i_ext(last_challenge, round_index);
        let mul_poly_ext = self.circuit.mul_i_ext(last_challenge, round_index);
        let mut sc_ver = ScVerifier::new(var_count, None);
        sc_ver.set_c_1(init_challenge);

        self.inner_state = VerifierInnerState::InSumCheck {
            combined_rand: Vec::new(),
            sc_verifier: Box::new(sc_ver),
            add_poly: add_poly_ext,
            mul_poly: mul_poly_ext,
        };

        Ok(VerifierResponse::RoundInitiated(round_index))
    }

    /// Generate the final random challenge in the sum-check protocol.
    #[inline]
    pub fn generate_final_challenge<R: Rng>(&mut self, rng: &mut R) -> GkrResult<VerifierResponse<F>> {
        if let VerifierInnerState::InSumCheck { combined_rand, .. } = &mut self.inner_state {
            let final_challenge = F::rand(rng);
            combined_rand.push(final_challenge);

            Ok(VerifierResponse::ScRoundResult {
                result: ScVerifierRoundResult::JthRound(final_challenge),
            })
        } else {
            Err(GkrError::InvalidVerifierState)
        }
    }

    #[inline]
    fn process_sc_step<R: Rng>(
        &mut self,
        poly_msg: univariate::SparsePolynomial<F>,
        rng: &mut R,
    ) -> GkrResult<VerifierResponse<F>> {
        if let VerifierInnerState::InSumCheck { combined_rand, sc_verifier, .. } = &mut self.inner_state {
            let sc_result = sc_verifier.round(poly_msg, rng)
                .expect("Sum-check round failed");

            if let ScVerifierRoundResult::JthRound(challenge) = sc_result {
                combined_rand.push(challenge);
            }

            Ok(VerifierResponse::ScRoundResult { result: sc_result })
        } else {
            Err(GkrError::InvalidVerifierState)
        }
    }

    #[inline]
    fn finalize_round<R: Rng>(
        &mut self,
        poly_p: univariate::SparsePolynomial<F>,
        poly_q: univariate::SparsePolynomial<F>,
        rng: &mut R,
    ) -> GkrResult<VerifierResponse<F>> {
        if let VerifierInnerState::InSumCheck {
            combined_rand,
            add_poly,
            mul_poly,
            ..
        } = &self.inner_state
        {
            // TODO: verify the degree of q.
            let q_at_zero = poly_q.evaluate(&F::zero());
            let q_at_one = poly_q.evaluate(&F::one());
            let eval_val = add_poly.evaluate(combined_rand).expect("Evaluation failed")
                * (q_at_zero + q_at_one)
                + mul_poly.evaluate(combined_rand).expect("Evaluation failed")
                    * q_at_zero
                    * q_at_one;

            assert_eq!(eval_val, poly_p.evaluate(combined_rand.last().unwrap()));

            let new_rand = F::rand(rng);
            let (b_vec, c_vec) = combined_rand.split_at(combined_rand.len() / 2);
            let line_polys = create_line_polynomials(b_vec, c_vec);
            let next_challenges: Vec<F> = line_polys
                .into_iter()
                .map(|p| p.evaluate(&new_rand))
                .collect();
            let next_accum = poly_q.evaluate(&new_rand);

            self.challenge_history.push(next_challenges.clone());
            self.output_accum.push(next_accum);

            Ok(VerifierResponse::Challenge { challenges: next_challenges })
        } else {
            Err(GkrError::InvalidVerifierState)
        }
    }

    /// Handle a message from the prover.
    pub fn handle_prover_message<R: Rng>(
        &mut self,
        msg: ProverMessage<F>,
        rng: &mut R,
    ) -> GkrResult<VerifierResponse<F>> {
        match msg {
            ProverMessage::ScProverMessage { poly } => self.process_sc_step(poly, rng),
            ProverMessage::StartSc { c_1, round, num_vars } => self.begin_round(c_1, round, num_vars),
            ProverMessage::FinalScMessage { poly: poly_p, poly_q } => self.finalize_round(poly_p, poly_q, rng),
            ProverMessage::Begin { outputs } => {
                let num_out_vars = self.circuit.num_vars_at(0).expect("Missing output variables");
                let d = DenseMultilinearExtension::from_evaluations_slice(num_out_vars, &outputs);
                let r0: Vec<F> = (0..num_out_vars).map(|_| F::rand(rng)).collect();
                let m0 = d.evaluate(&r0).expect("Evaluation failed");

                self.challenge_history = vec![r0.clone()];
                self.output_accum = vec![m0];

                Ok(VerifierResponse::Challenge { challenges: r0 })
            }
        }
    }

    /// Validate the input by comparing the MLE of the input with the final accumulated value.
    #[inline]
    pub fn validate_input(&self, input: &[F]) -> bool {
        let var_count = (f64::from(input.len() as u32)).log2() as usize;
        let input_poly = DenseMultilinearExtension::from_evaluations_slice(var_count, input);
        input_poly.evaluate(self.challenge_history.last().unwrap()).expect("Evaluation failed")
            == *self.output_accum.last().unwrap()
    }
}

/// Messages emitted by the verifier.
#[derive(Debug)]
pub enum VerifierResponse<F: Field> {
    /// Result of a sum-check round.
    ScRoundResult { result: ScVerifierRoundResult<F> },
    /// Indicates the first round is complete.
    FirstRound,
    /// Indicates that round `i` has started.
    RoundInitiated(usize),
    /// Contains the challenge vector \( r_i \) to be sent to the prover.
    Challenge { challenges: Vec<F> },
}

/// Messages sent by the prover.
#[derive(Debug, PartialEq, Eq)]
pub enum ProverMessage<F: Field> {
    /// The prover begins by claiming the circuit outputs.
    Begin { outputs: Vec<F> },
    /// A sum-check round message from the prover.
    ScProverMessage { poly: univariate::SparsePolynomial<F> },
    /// In the final round, the restriction polynomial is sent.
    FinalScMessage {
        poly: univariate::SparsePolynomial<F>,
        poly_q: univariate::SparsePolynomial<F>,
    },
    /// Instructs the verifier to start a sum-check round.
    StartSc { c_1: F, round: usize, num_vars: usize },
}

/// Create a set of univariate polynomials representing a line between two vectors.
///
/// Given \( b, c \in \mathbb{F}^{\log n} \), returns polynomials \( l_i \) such that
/// \( l_i(0) = b_i \) and \( l_i(1) = c_i \).
#[inline]
pub fn create_line_polynomials<F: Field>(
    b: &[F],
    c: &[F],
) -> Vec<univariate::SparsePolynomial<F>> {
    iter::zip(b, c)
        .map(|(b_val, c_val)| {
            univariate::SparsePolynomial::from_coefficients_slice(&[(0, *b_val), (1, *c_val - b_val)])
        })
        .collect()
}

/// Restrict a multilinear extension to a line defined by two points.
///
/// Given \( b, c \in \mathbb{F}^{\log n} \), computes the line \( l(t) \) such that
/// \( l(0)=b \) and \( l(1)=c \), and restricts the MLE to this line to yield a univariate polynomial.
#[inline]
pub fn restrict_polynomial_to_line<F: Field, M: MultilinearExtension<F>>(
    b: &[F],
    c: &[F],
    mle: &M,
) -> univariate::SparsePolynomial<F> {
    let delta: Vec<F> = iter::zip(b, c).map(|(bi, ci)| *ci - bi).collect();
    let evals = mle.to_evaluations();
    let var_count = mle.num_vars();
    let one_dense_poly: univariate::DensePolynomial<F> =
        univariate::DensePolynomial::from_coefficients_vec(vec![F::one()]);
    let mut result_poly = univariate::SparsePolynomial::zero();

    for (i, &val) in evals.iter().enumerate() {
        let mut temp_poly = univariate::SparsePolynomial::from_coefficients_vec(vec![(0, val)]);
        for bit in 0..var_count {
            let mut aux_poly = univariate::SparsePolynomial::from_coefficients_vec(vec![
                (0, b[bit]),
                (1, delta[bit]),
            ]);
            if i & (1 << bit) == 0 {
                aux_poly = (&one_dense_poly - &aux_poly).into();
            }
            temp_poly = temp_poly.mul(&aux_poly);
        }
        result_poly += &temp_poly;
    }
    result_poly
}

/// The state of the prover.
pub struct GkrProver<F: FftField> {
    /// Current protocol round.
    current_round: usize,
    /// The circuit.
    circuit: Circuit,
    /// Evaluation of the circuit on the given input.
    circuit_eval: CircuitEvaluation<F>,
    /// Sum-check prover instance.
    sc_prover: Option<ScProver<F, W<F>>>,
    /// Polynomial \( \tilde{W}_{i+1} \) for the next layer.
    next_layer_poly: DenseMultilinearExtension<F>,
    /// History of challenges received.
    challenge_history: Vec<F>,
}

impl<F: FftField> GkrProver<F> {
    /// Create a new `GkrProver` from a circuit and input.
    pub fn new(circ: Circuit, input: &[F]) -> Self {
        let eval = circ.evaluate(input);
        Self {
            current_round: 0,
            circuit: circ,
            circuit_eval: eval,
            sc_prover: None,
            next_layer_poly: Default::default(),
            challenge_history: Vec::new(),
        }
    }

    /// Start the protocol by sending the circuit outputs.
    pub fn initiate_protocol(&self) -> ProverMessage<F> {
        ProverMessage::Begin {
            outputs: self.circuit_eval.layers.first().unwrap().clone(),
        }
    }

    /// Begin a new sum-check round for the current layer.
    ///
    /// Constructs the polynomial \( f^{(i)}_{r_i}(b,c) \) for the round.
    pub fn start_sc_round(&mut self, round_index: usize, r_i: &[F]) -> ProverMessage<F> {
        let current_vars = self
            .circuit
            .num_vars_at(round_index)
            .expect("Missing current variable count");
        let next_vars = self
            .circuit
            .num_vars_at(round_index + 1)
            .expect("Missing next variable count");

        let poly_b = DenseMultilinearExtension::from_evaluations_slice(next_vars, &self.circuit_eval.layers[round_index + 1]);
        self.next_layer_poly = poly_b.clone();
        let poly_c = poly_b.clone();

        let next_bound = 2usize.pow(next_vars as u32);
        let current_bound = 2usize.pow(current_vars as u32);
        let total_evals = next_bound * next_bound * current_bound;
        let mut add_poly_vec = Vec::with_capacity(total_evals);
        let mut mul_poly_vec = Vec::with_capacity(total_evals);

        for c in 0..next_bound {
            for b in 0..next_bound {
                for a in 0..current_bound {
                    add_poly_vec.push(if self.circuit.add_i(round_index, a, b, c) {
                        F::one()
                    } else {
                        F::zero()
                    });
                    mul_poly_vec.push(if self.circuit.mul_i(round_index, a, b, c) {
                        F::one()
                    } else {
                        F::zero()
                    });
                }
            }
        }

        let fixed_add_poly = DenseMultilinearExtension::from_evaluations_vec(current_vars + next_vars * 2, add_poly_vec)
            .fix_variables(r_i);
        let fixed_mul_poly = DenseMultilinearExtension::from_evaluations_vec(current_vars + next_vars * 2, mul_poly_vec)
            .fix_variables(r_i);

        assert_eq!(fixed_add_poly.num_vars(), fixed_mul_poly.num_vars());
        assert_eq!(fixed_add_poly.num_vars(), 2 * poly_b.num_vars());

        let round_poly = W::new(fixed_add_poly, fixed_mul_poly, poly_b, poly_c);
        self.current_round = round_index;

        let mut sc_prover_inst = ScProver::new(round_poly);
        let init_challenge = sc_prover_inst.c_1();
        self.sc_prover = Some(sc_prover_inst);
        self.challenge_history.clear();

        ProverMessage::StartSc {
            c_1: init_challenge,
            round: round_index,
            num_vars: round_poly.num_vars(),
        }
    }

    /// Compose a message for a given round of the sum-check protocol.
    pub fn compose_round_message(&mut self, j: usize) -> ProverMessage<F> {
        let next_vars = self
            .circuit
            .num_vars_at(self.current_round + 1)
            .expect("Missing next variable count");
        let last_round = 2 * next_vars - 1;
        if j == last_round {
            // Final round: restrict polynomial.
            let mid = self.challenge_history.len() / 2;
            let (b_slice, c_slice) = self.challenge_history.split_at(mid);
            let poly_q = restrict_polynomial_to_line(b_slice, c_slice, &self.next_layer_poly);
            let poly_p = self.sc_prover.as_mut().unwrap().round(self.challenge_history[j - 1], j);
            ProverMessage::FinalScMessage { poly: poly_p, poly_q }
        } else {
            let point = if j == 0 { F::one() } else { self.challenge_history[j - 1] };
            ProverMessage::ScProverMessage {
                poly: self.sc_prover.as_mut().unwrap().round(point, j),
            }
        }
    }

    /// Handle a response from the verifier.
    pub fn handle_verifier_response(&mut self, response: VerifierResponse<F>) {
        if let VerifierResponse::ScRoundResult { result } = response {
            if let ScVerifierRoundResult::JthRound(challenge) = result {
                self.challenge_history.push(challenge);
            } else {
                panic!("Unexpected final round message received");
            }
        }
    }

    /// Retrieve the current sum-check initial challenge.
    #[inline]
    pub fn get_initial_challenge(&self) -> F {
        self.sc_prover.as_ref().unwrap().c_1()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{Fp64, MontBackend, MontConfig, PrimeField};
    use ark_poly::univariate::DensePolynomial;
    use ark_std::test_rng;
    use circuit::circuit_from_book;
    use pretty_assertions::assert_eq;
    use crate::circuit::{CircuitLayer, Gate, GateType};
    use super::*;

    fn three_layer_circuit() -> Circuit {
        Circuit::new(
            vec![
                CircuitLayer::new(vec![
                    Gate::new(GateType::Add, [0, 1]),
                    Gate::new(GateType::Add, [2, 3]),
                ]),
                CircuitLayer::new(vec![
                    Gate::new(GateType::Add, [0, 1]),
                    Gate::new(GateType::Add, [2, 3]),
                    Gate::new(GateType::Add, [4, 5]),
                    Gate::new(GateType::Add, [6, 7]),
                ]),
            ],
            8,
        )
    }

    #[test]
    /// Test the polynomial restriction function.
    fn test_restrict_polynomial_to_line() {
        #[derive(MontConfig)]
        #[modulus = "389"]
        #[generator = "2"]
        struct FrConfig;

        type Fp389 = Fp64<MontBackend<FrConfig, 1>>;

        let b = [
            Fp389::from_bigint(2u32.into()).unwrap(),
            Fp389::from_bigint(4u32.into()).unwrap(),
        ];
        let c = [
            Fp389::from_bigint(3u32.into()).unwrap(),
            Fp389::from_bigint(2u32.into()).unwrap(),
        ];
        let evals = [
            Fp389::from_bigint(0u32.into()).unwrap(),
            Fp389::from_bigint(0u32.into()).unwrap(),
            Fp389::from_bigint(2u32.into()).unwrap(),
            Fp389::from_bigint(5u32.into()).unwrap(),
        ];

        let poly = restrict_polynomial_to_line(
            &b,
            &c,
            &DenseMultilinearExtension::from_evaluations_slice(2, &evals),
        );
        let dense_poly: DensePolynomial<Fp389> = poly.into();
        // Expected polynomial: -6t^2 - 4t + 32
        assert_eq!(
            vec![32, 385, 383],
            dense_poly.coeffs().iter().map(|c| c.into_bigint().as_ref()[0]).collect::<Vec<_>>()
        );
    }

    #[test]
    fn protocol_test_from_book() {
        let rng = &mut test_rng();
        #[derive(MontConfig)]
        #[modulus = "389"]
        #[generator = "2"]
        struct FrConfig;
        type Fp389 = Fp64<MontBackend<FrConfig, 1>>;
        let circuit = circuit_from_book();
        let input = [
            Fp389::from_bigint(3u32.into()).unwrap(),
            Fp389::from_bigint(2u32.into()).unwrap(),
            Fp389::from_bigint(3u32.into()).unwrap(),
            Fp389::from_bigint(1u32.into()).unwrap(),
        ];
        let expected_outputs = [
            Fp389::from_bigint(36u32.into()).unwrap(),
            Fp389::from_bigint(6u32.into()).unwrap(),
        ];
        let mut prover = GkrProver::new(circuit.clone(), &input);
        let outputs_msg = prover.initiate_protocol();
        assert_eq!(
            outputs_msg,
            ProverMessage::Begin { outputs: expected_outputs.to_vec() }
        );
        let mut verifier = GkrVerifier::new(circuit.clone());
        let verifier_resp = verifier.handle_prover_message(outputs_msg, rng).unwrap();
        let mut r_vec = match verifier_resp {
            VerifierResponse::Challenge { challenges } => challenges,
            _ => panic!(),
        };
        for i in 0..circuit.layers().len() {
            let start_msg = prover.start_sc_round(i, &r_vec);
            verifier.handle_prover_message(start_msg, rng).unwrap();
            let num_vars = 2 * circuit.num_vars_at(i + 1).unwrap();
            for j in 0..(num_vars - 1) {
                let p_msg = prover.compose_round_message(j);
                let v_resp = verifier.handle_prover_message(p_msg, rng).unwrap();
                prover.handle_verifier_response(v_resp);
            }
            let final_rand = verifier.generate_final_challenge(rng).unwrap();
            prover.handle_verifier_response(final_rand);
            let last_msg = prover.compose_round_message(num_vars - 1);
            let final_resp = verifier.handle_prover_message(last_msg, rng).unwrap();
            r_vec = match final_resp {
                VerifierResponse::Challenge { challenges } => challenges,
                _ => panic!("{:?}", final_resp),
            };
        }
        assert!(verifier.validate_input(&input));
    }

    #[test]
    fn three_layer_protocol_test() {
        let rng = &mut test_rng();
        #[derive(MontConfig)]
        #[modulus = "389"]
        #[generator = "2"]
        struct FrConfig;
        type Fp389 = Fp64<MontBackend<FrConfig, 1>>;
        let circuit = three_layer_circuit();
        let input = [
            Fp389::from_bigint(0u32.into()).unwrap(),
            Fp389::from_bigint(1u32.into()).unwrap(),
            Fp389::from_bigint(0u32.into()).unwrap(),
            Fp389::from_bigint(1u32.into()).unwrap(),
            Fp389::from_bigint(0u32.into()).unwrap(),
            Fp389::from_bigint(1u32.into()).unwrap(),
            Fp389::from_bigint(0u32.into()).unwrap(),
            Fp389::from_bigint(1u32.into()).unwrap(),
        ];
        let expected_outputs = [
            Fp389::from_bigint(2u32.into()).unwrap(),
            Fp389::from_bigint(2u32.into()).unwrap(),
        ];
        let mut prover = GkrProver::new(circuit.clone(), &input);
        let outputs_msg = prover.initiate_protocol();
        assert_eq!(
            outputs_msg,
            ProverMessage::Begin { outputs: expected_outputs.to_vec() }
        );
        let mut verifier = GkrVerifier::new(circuit.clone());
        let verifier_resp = verifier.handle_prover_message(outputs_msg, rng).unwrap();
        let mut r_vec = match verifier_resp {
            VerifierResponse::Challenge { challenges } => challenges,
            _ => panic!(),
        };
        for i in 0..circuit.layers().len() {
            let start_msg = prover.start_sc_round(i, &r_vec);
            verifier.handle_prover_message(start_msg, rng).unwrap();
            let num_vars = 2 * circuit.num_vars_at(i + 1).unwrap();
            for j in 0..(num_vars - 1) {
                let p_msg = prover.compose_round_message(j);
                let v_resp = verifier.handle_prover_message(p_msg, rng).unwrap();
                prover.handle_verifier_response(v_resp);
            }
            let final_rand = verifier.generate_final_challenge(rng).unwrap();
            prover.handle_verifier_response(final_rand);
            let last_msg = prover.compose_round_message(num_vars - 1);
            let final_resp = verifier.handle_prover_message(last_msg, rng).unwrap();
            r_vec = match final_resp {
                VerifierResponse::Challenge { challenges } => challenges,
                _ => panic!("{:?}", final_resp),
            };
        }
        assert!(verifier.validate_input(&input));
    }
}
