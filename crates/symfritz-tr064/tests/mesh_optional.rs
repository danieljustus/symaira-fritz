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

#[test]
fn mesh_links_resolve_peers_from_the_uid_keys_fritzos_actually_sends() {
    // FRITZ!OS 8.x names the endpoints `node_1_uid` / `node_2_uid`. Reading only
    // the bare `node_1` / `node_2` spelling left every peer name blank.
    let topology = parse_mesh_topology(
        br#"{"schema_version":"8.7","nodes":[
            {"uid":"n-1","device_name":"fritz-box4060","node_interfaces":[
                {"uid":"ni-19","type":"LAN","node_links":[
                    {"state":"CONNECTED","node_1_uid":"n-1","node_2_uid":"n-184",
                     "node_interface_1_uid":"ni-19","node_interface_2_uid":"ni-185",
                     "max_data_rate_rx":1000000,"max_data_rate_tx":1000000,
                     "cur_data_rate_rx":1000000,"cur_data_rate_tx":1000000}]}]},
            {"uid":"n-184","device_name":"ps5slim","node_interfaces":[]}]}"#,
    )
    .expect("FRITZ!OS mesh list parses");

    let link = &topology.nodes[0].node_interfaces[0].node_links[0];
    assert_eq!(link.node_1, "n-1");
    assert_eq!(link.node_2, "n-184");
    assert_eq!(topology.node_name(&link.node_2), "ps5slim");
}

#[test]
fn mesh_still_accepts_the_bare_node_key_spelling() {
    let topology = parse_mesh_topology(
        br#"{"nodes":[{"uid":"n1","device_name":"box","node_interfaces":[
            {"uid":"i1","type":"LAN","node_links":[{"state":"CONNECTED","node_1":"n1","node_2":"n2"}]}]}]}"#,
    )
    .expect("legacy spelling still parses");

    let link = &topology.nodes[0].node_interfaces[0].node_links[0];
    assert_eq!(link.node_1, "n1");
    assert_eq!(link.node_2, "n2");
}
