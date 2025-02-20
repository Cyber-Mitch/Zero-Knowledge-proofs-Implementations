use sha2::{Digest, Sha256};

/// A simple Fiat–Shamir transcript.
pub struct Transcript {
    data: Vec<u8>,
}

impl Transcript {
    /// Creates a new, empty transcript.
    pub fn new() -> Self {
        Transcript { data: Vec::new() }
    }

    /// Appends a message (as a byte slice) to the transcript.
    /// For robustness, consider adding delimiters or length prefixes.
    pub fn append_message(&mut self, message: &[u8]) {
        self.data.extend_from_slice(message);
    }

    /// Computes the current challenge by hashing the transcript using SHA‑256.
    /// Returns a 32-byte array.
    pub fn get_challenge(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let result = hasher.finalize();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&result);
        challenge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_transcript() {
        let transcript = Transcript::new();
        let challenge = transcript.get_challenge();
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(challenge, expected);
    }

    #[test]
    fn test_append_message_changes_challenge() {
        let mut transcript = Transcript::new();
        let challenge_empty = transcript.get_challenge();
        transcript.append_message(b"test message");
        let challenge_after = transcript.get_challenge();
        assert_ne!(challenge_empty, challenge_after);
    }

    #[test]
    fn test_consistency() {
        let mut transcript1 = Transcript::new();
        transcript1.append_message(b"message A");
        transcript1.append_message(b"message B");

        let mut transcript2 = Transcript::new();
        transcript2.append_message(b"message A");
        transcript2.append_message(b"message B");

        assert_eq!(transcript1.get_challenge(), transcript2.get_challenge());
    }
}
