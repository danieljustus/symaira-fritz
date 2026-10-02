#![deny(unsafe_code)]

use symfritz_tr064::{DslLineStats, Host, TrafficData};

#[test]
fn zero_and_default_typed_capabilities_serialize_without_omitted_defaults() {
    assert_eq!(
        serde_json::to_value(DslLineStats::default()).unwrap(),
        serde_json::json!({})
    );
    assert_eq!(
        serde_json::to_value(TrafficData::default()).unwrap(),
        serde_json::json!({})
    );
    assert_eq!(Host::default().link(), "—");

    let dsl = DslLineStats {
        upstream_noise_margin: 60,
        downstream_max_bit_rate: 100_000_000,
        is_reduced_dataset: true,
        ..DslLineStats::default()
    };
    let json = serde_json::to_value(dsl).unwrap();
    assert_eq!(json["upstream_noise_margin"], 60);
    assert_eq!(json["downstream_max_bit_rate"], 100_000_000);
    assert_eq!(json["is_reduced_dataset"], true);

    let traffic = TrafficData {
        downstream_internet: vec![1.5, 2.5],
        is_reduced_dataset: true,
        ..TrafficData::default()
    };
    let json = serde_json::to_value(traffic).unwrap();
    assert_eq!(json["downstream_internet"], serde_json::json!([1.5, 2.5]));
    assert_eq!(json["is_reduced_dataset"], true);
}
