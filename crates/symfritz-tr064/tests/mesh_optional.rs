#![deny(unsafe_code)]

use symfritz_tr064::parse_mesh_topology;

#[test]
fn mesh_missing_optional_link_fields_match_go_zero_values() {
    let topology = parse_mesh_topology(
        br#"{"schema_version":"1.0","nodes":[{"uid":"node","node_interfaces":[{"uid":"if","type":"LAN","node_links":[{"state":"DISCONNECTED"}]}]}]}"#,
    )
    .expect("Go json.Unmarshal accepts missing mesh fields");

    let node = &topology.nodes[0];
    assert_eq!(node.device_name, "");
    let link = &node.node_interfaces[0].node_links[0];
    assert_eq!(link.node_1, "");
    assert_eq!(link.node_2, "");
    assert_eq!(link.max_data_rate_rx, 0);
    assert_eq!(link.cur_data_rate_tx, 0);
}
