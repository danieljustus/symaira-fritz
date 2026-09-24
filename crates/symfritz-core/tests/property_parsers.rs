#![deny(unsafe_code)]

use proptest::prelude::*;
use symfritz_core::auth::{
    ChallengeError, MAX_PBKDF2_ITERATIONS, challenge_response, parse_digest_challenge,
};

proptest! {
    #[test]
    fn digest_parser_accepts_arbitrary_text_without_panicking(header in "[\\x00-\\x7f]{0,512}") {
        let _ = parse_digest_challenge(&header);
    }

    #[test]
    fn legacy_auth_response_is_deterministic(
        challenge in "[a-zA-Z0-9_-]{1,64}",
        password in "[a-zA-Z0-9_!.-]{0,64}",
    ) {
        let first = challenge_response(&challenge, &password).unwrap();
        let second = challenge_response(&challenge, &password).unwrap();
        prop_assert_eq!(&first, &second);
        let prefix = format!("{}-", challenge);
        prop_assert!(first.starts_with(&prefix), "prefix={}", prefix);
    }

    #[test]
    fn malformed_modern_auth_challenge_is_bounded(salt in "[0-9a-f]{0,64}") {
        let challenge = format!("2$0${salt}$0${salt}");
        let _ = challenge_response(&challenge, "password");
    }

    #[test]
    fn excessive_iteration_field_is_rejected_in_either_position(
        ordinary in 0_u64..=u64::from(MAX_PBKDF2_ITERATIONS),
        hostile in (u64::from(MAX_PBKDF2_ITERATIONS) + 1)..=i64::MAX.unsigned_abs(),
    ) {
        // Covers the hostile work factor the zero-count property test above
        // cannot reach: both field positions must be rejected with the
        // out-of-bounds error before either KDF, so every case stays fast.
        for challenge in [
            format!("2${ordinary}$0a0b${hostile}$0c0d"),
            format!("2${hostile}$0a0b${ordinary}$0c0d"),
        ] {
            prop_assert_eq!(
                challenge_response(&challenge, "password"),
                Err(ChallengeError::Pbkdf2IterationCountOutOfBounds)
            );
        }
    }
}
