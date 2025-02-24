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
        // Here we use FixedRandom to supply the challenge.
        if !verifier.execute_round(round, msg, &mut FixedRandom::new(vec![challenge]))? {
            return Ok(false);
        }
    }
    Ok(true)
}
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
        // Here we use FixedRandom to supply the challenge.
        if !verifier.execute_round(round, msg, &mut FixedRandom::new(vec![challenge]))? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as ScalarField;
    use ark_ff::Field;
    use sum_check_protocol::DefaultFieldHasher;
    use ark_serialize::CanonicalSerialize;

    /// A dummy interactive prover for testing FS.
    struct DummyFSProver {
        total_rounds: usize,
    }

    impl DummyFSProver {
        fn new(total_rounds: usize) -> Self {
            Self { total_rounds }
        }
    }

    impl FSProverInterface<ScalarField> for DummyFSProver {
        fn get_initial_message(&mut self) -> FSResult<Vec<u8>> {
            // Return a fixed initial message.
            Ok(b"dummy_initial".to_vec())
        }

        fn perform_round(&mut self, round_index: usize, challenge: ScalarField) -> FSResult<Vec<u8>> {
            // Create a dummy round message that includes the round index and the challenge.
            let mut msg = format!("dummy_round{}", round_index).into_bytes();
            // Append the challenge's canonical serialization.
            challenge.serialize_uncompressed(&mut msg)
                .map_err(|_| FSSError::Serialization)?;
            Ok(msg)
        }

        fn rounds_count(&self) -> usize {
            self.total_rounds
        }
    }

    /// A dummy interactive verifier for testing FS.
    struct DummyFSVerifier {
        total_rounds: usize,
    }

    impl DummyFSVerifier {
        fn new(total_rounds: usize) -> Self {
            Self { total_rounds }
        }
    }

    impl FSVerifierInterface<ScalarField, FixedRandom<ScalarField>> for DummyFSVerifier {
        fn execute_round(&mut self, round_index: usize, msg: &[u8], _rng: &mut FixedRandom<ScalarField>) -> FSResult<bool> {
            // Check that the message begins with "dummy_round{round_index}".
            let expected_prefix = format!("dummy_round{}", round_index);
            Ok(msg.starts_with(expected_prefix.as_bytes()))
        }
    }

    #[test]
    fn test_fs_transcript_creation_and_verification() {
        let total_rounds = 3;
        let prover = DummyFSProver::new(total_rounds);

        // Create a transcript using the DefaultFieldHasher.
        let transcript = create_fs_transcript::<ScalarField, _, DefaultFieldHasher<_>>(prover)
            .expect("Failed to create FS transcript");

        // Create a dummy verifier.
        let verifier = DummyFSVerifier::new(total_rounds);

        // Verify the transcript.
        let valid = verify_fs_transcript::<ScalarField, _, DefaultFieldHasher<_>>(transcript, verifier)
            .expect("FS transcript verification failed");

        assert!(valid, "The FS transcript should verify as valid");
    }
}
