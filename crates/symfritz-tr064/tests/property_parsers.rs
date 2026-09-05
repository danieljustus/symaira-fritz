#![deny(unsafe_code)]

use proptest::prelude::*;
use std::collections::BTreeMap;
use symfritz_tr064::{build_request, parse_fault, parse_response};

proptest! {
    #[test]
    fn soap_xml_parsers_accept_arbitrary_bytes_without_panicking(xml in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_response(&xml, "GetInfo");
        let _ = parse_fault(&xml);
    }

    #[test]
    fn soap_request_escaping_preserves_argument_boundaries(value in "[\\x00-\\x7f]{0,256}") {
        let arguments = BTreeMap::from([(String::from("Value"), value.clone())]);
        let request = build_request("urn:test", "GetInfo", &arguments);
        let text = String::from_utf8(request).unwrap();
        prop_assert!(text.contains("<Value>"));
        prop_assert!(text.contains("</Value>"));
        if !value.is_empty() {
            prop_assert!(!text.contains("<Value><"));
        }
    }
}
