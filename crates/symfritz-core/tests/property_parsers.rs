#![deny(unsafe_code)]

use proptest::prelude::*;
use symfritz_core::auth::{challenge_response, parse_digest_challenge};

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
}
