#![deny(unsafe_code)]

use std::{collections::BTreeMap, fs, path::PathBuf};

use serde::Deserialize;
use symfritz_tr064::{
    Service, build_request, find_service_by_name, parse_description, parse_fault, parse_response,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    soap_requests: Vec<SoapRequestVector>,
    soap_responses: Vec<SoapResponseVector>,
    soap_faults: Vec<SoapFaultVector>,
    discovery: Vec<DiscoveryVector>,
    service_lookup: Vec<ServiceLookupVector>,
}

#[derive(Debug, Deserialize)]
struct SoapRequestVector {
    id: String,
    service_type: String,
    action: String,
    args: BTreeMap<String, String>,
    body: String,
}

#[derive(Debug, Deserialize)]
struct SoapResponseVector {
    id: String,
    action: String,
    xml: String,
    #[serde(default)]
    output: BTreeMap<String, String>,
    #[serde(default)]
    error: bool,
}

#[derive(Debug, Deserialize)]
struct SoapFaultVector {
    id: String,
    xml: String,
    code: i32,
    description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ServiceVector {
    #[serde(rename = "type")]
    service_type: String,
    control_url: String,
}

#[derive(Debug, Deserialize)]
struct DiscoveryVector {
    id: String,
    #[serde(default)]
    input_file: String,
    #[serde(default)]
    xml: String,
    #[serde(default)]
    services: Vec<ServiceVector>,
    #[serde(default)]
    error: bool,
}

#[derive(Debug, Deserialize)]
struct ServiceLookupVector {
    id: String,
    name: String,
    service: Option<ServiceVector>,
    #[serde(default)]
    error: String,
}

impl From<Service> for ServiceVector {
    fn from(value: Service) -> Self {
        Self {
            service_type: value.service_type,
            control_url: value.control_url,
        }
    }
}

fn fixture() -> Fixture {
    let path = repository_root().join("testdata/port/tr064/contracts.json");
    let bytes = fs::read(path).expect("read Go TR-064 fixture");
    serde_json::from_slice(&bytes).expect("parse Go TR-064 fixture")
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn fixture_metadata_is_current() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/fritz production SOAP and discovery functions"
    );
}

#[test]
fn soap_requests_match_go_byte_for_byte() {
    for vector in fixture().soap_requests {
        assert_eq!(
            build_request(&vector.service_type, &vector.action, &vector.args),
            vector.body.as_bytes(),
            "{}",
            vector.id
        );
    }
}

#[test]
fn soap_responses_match_go() {
    for vector in fixture().soap_responses {
        let actual = parse_response(vector.xml.as_bytes(), &vector.action);
        if vector.error {
            assert!(actual.is_err(), "{}: expected parse error", vector.id);
        } else {
            assert_eq!(actual.unwrap(), vector.output, "{}", vector.id);
        }
    }
}

#[test]
fn soap_faults_match_go() {
    for vector in fixture().soap_faults {
        assert_eq!(
            parse_fault(vector.xml.as_bytes()),
            (vector.code, vector.description),
            "{}",
            vector.id
        );
    }
}

#[test]
fn discovery_matches_go() {
    for vector in fixture().discovery {
        let input = if vector.input_file.is_empty() {
            vector.xml.into_bytes()
        } else {
            fs::read(repository_root().join(vector.input_file)).unwrap()
        };
        let actual = parse_description(&input);
        if vector.error {
            assert!(actual.is_err(), "{}: expected discovery error", vector.id);
        } else {
            let actual: Vec<_> = actual
                .unwrap()
                .into_iter()
                .map(ServiceVector::from)
                .collect();
            assert_eq!(actual, vector.services, "{}", vector.id);
        }
    }
}

#[test]
fn service_lookup_matches_go() {
    let fixture = fixture();
    let description = fs::read(repository_root().join("internal/fritz/testdata/tr64desc.xml"))
        .expect("read discovery input");
    let services = parse_description(&description).unwrap();
    for vector in fixture.service_lookup {
        let actual = find_service_by_name(&services, &vector.name);
        if vector.error.is_empty() {
            assert_eq!(
                ServiceVector::from(actual.unwrap()),
                vector.service.expect("expected service fixture"),
                "{}",
                vector.id
            );
        } else {
            assert_eq!(
                actual.unwrap_err().to_string(),
                vector.error,
                "{}",
                vector.id
            );
        }
    }
}
