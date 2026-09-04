use std::{
    collections::BTreeMap,
    io::Read,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    str, thread,
    time::Duration,
};

use crate::{Client, ClientError, CnonceSource, Method, Request, Service, Transport};
use roxmltree::Document;
use serde::{Deserialize, Serialize};

const MAX_DIAGNOSIS_WORKERS: usize = 8;
const MESH_RESPONSE_LIMIT: usize = 8 << 20;

/// Error categories shared by typed capability reports.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Unauthorized,
    ServiceUnavailable,
    UnsupportedAction,
    Timeout,
    Transport,
    Internal,
    #[default]
    Unknown,
}

/// Classify a protocol error without exposing transport implementation details.
#[must_use]
pub fn error_kind(error: &ClientError) -> ErrorKind {
    match error {
        ClientError::UnauthorizedChallenge => ErrorKind::Unauthorized,
        ClientError::SoapFault {
            code, description, ..
        } => match code {
            401 | 402 => ErrorKind::UnsupportedAction,
            606 => ErrorKind::Unauthorized,
            713 | 714 => ErrorKind::ServiceUnavailable,
            501 | 603 | 820 => ErrorKind::Internal,
            _ if description.to_ascii_lowercase().contains("invalid action") => {
                ErrorKind::UnsupportedAction
            }
            _ if description.to_ascii_lowercase().contains("no such entry") => {
                ErrorKind::ServiceUnavailable
            }
            _ => ErrorKind::Unknown,
        },
        ClientError::Transport(message) => {
            let message = message.to_ascii_lowercase();
            if message.contains("timeout") || message.contains("timed out") {
                ErrorKind::Timeout
            } else {
                ErrorKind::Transport
            }
        }
        ClientError::Cnonce(_) => ErrorKind::Internal,
        ClientError::DiscoveryHttpStatus(_) | ClientError::Discovery(_) => {
            ErrorKind::ServiceUnavailable
        }
        ClientError::SoapParse(_) => ErrorKind::Internal,
    }
}

fn is_unauthorized(error: &ClientError) -> bool {
    error_kind(error) == ErrorKind::Unauthorized
}

fn is_unsupported(error: &ClientError) -> bool {
    error_kind(error) == ErrorKind::UnsupportedAction
}

/// High-level overview assembled from four independent TR-064 queries.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Status {
    pub model_name: String,
    pub firmware_version: String,
    pub external_ip: String,
    pub connection_state: String,
    pub uptime: String,
    pub update_available: String,
    pub partial: bool,
    pub errors: Vec<StatusError>,
}

/// One failed sub-query in a [`Status`] report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusError {
    pub service: String,
    pub action: String,
    pub message: String,
    pub kind: ErrorKind,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}/{}: {}",
            self.service, self.action, self.message
        )
    }
}

/// Firmware update availability from the UserInterface service.
impl<T: Transport, C: CnonceSource> Client<T, C> {
    /// Fetch the box overview. Partial failures are retained in `Status`; an
    /// error is returned only when no useful primary data was obtained.
    pub fn status(&mut self) -> Result<Status, ClientError> {
        let mut status = Status::default();
        let mut errors = Vec::new();

        match self.call(&Service::device_info(), "GetInfo", &BTreeMap::new()) {
            Ok(values) => {
                status.model_name = values.get("NewModelName").cloned().unwrap_or_default();
                status.firmware_version = values
                    .get("NewSoftwareVersion")
                    .cloned()
                    .unwrap_or_default();
                status.uptime = values.get("NewUpTime").cloned().unwrap_or_default();
            }
            Err(error) => errors.push(StatusError::from_error("DeviceInfo", "GetInfo", &error)),
        }

        match self.wan_connection_call("GetInfo") {
            Ok(values) => {
                status.connection_state = values
                    .get("NewConnectionStatus")
                    .cloned()
                    .unwrap_or_default();
            }
            Err(error) => errors.push(StatusError::from_error("WANConnection", "GetInfo", &error)),
        }
        match self.wan_connection_call("GetExternalIPAddress") {
            Ok(values) => {
                status.external_ip = values
                    .get("NewExternalIPAddress")
                    .cloned()
                    .unwrap_or_default();
            }
            Err(error) => errors.push(StatusError::from_error(
                "WANConnection",
                "GetExternalIPAddress",
                &error,
            )),
        }
        match self.update_available() {
            Ok(version) => status.update_available = version,
            Err(error) => errors.push(StatusError::from_error("UserInterface", "GetInfo", &error)),
        }

        status.partial = !errors.is_empty();
        status.errors = errors;
        let no_primary_data = status.model_name.is_empty()
            && status.firmware_version.is_empty()
            && status.external_ip.is_empty()
            && status.connection_state.is_empty()
            && status.uptime.is_empty();
        if status.errors.len() == 4 || (no_primary_data && status.partial) {
            if let Some(error) = status
                .errors
                .iter()
                .find(|error| error.kind == ErrorKind::Unauthorized)
            {
                return Err(ClientError::Transport(error.message.clone()));
            }
            return Err(ClientError::Transport(status.errors.first().map_or_else(
                || "all status sub-queries failed".to_owned(),
                |error| error.message.clone(),
            )));
        }
        Ok(status)
    }

    /// Check whether a firmware upgrade is available.
    pub fn update_available(&mut self) -> Result<String, ClientError> {
        let response = self.call(&Service::user_interface(), "GetInfo", &BTreeMap::new())?;
        if response
            .get("NewUpgradeAvailable")
            .is_some_and(|value| value == "1")
        {
            Ok(response
                .get("NewX_AVM-DE_Version")
                .cloned()
                .unwrap_or_default())
        } else {
            Ok(String::new())
        }
    }

    fn wan_connection_call(
        &mut self,
        action: &str,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        match self.call(&Service::wan_ip_connection(), action, &BTreeMap::new()) {
            Ok(response) => Ok(response),
            Err(error) if is_unsupported(&error) => {
                match self.call(&Service::wan_ppp_connection(), action, &BTreeMap::new()) {
                    Ok(response) => Ok(response),
                    Err(fallback) => Err(ClientError::Transport(format!(
                        "WANIPConnection.{action} failed: {error}; WANPPPConnection.{action} fallback failed: {fallback}"
                    ))),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Return the full host table, using the bulk endpoint before indexed SOAP.
    pub fn hosts(&mut self) -> Result<Vec<Host>, ClientError> {
        match self.bulk_hosts() {
            Ok(hosts) => Ok(hosts),
            Err(_) => self.hosts_from_index(),
        }
    }

    fn bulk_hosts(&mut self) -> Result<Vec<Host>, ClientError> {
        let response = self.call(
            &Service::hosts(),
            "X_AVM-DE_GetHostListPath",
            &BTreeMap::new(),
        )?;
        let path = response
            .get("NewX_AVM-DE_HostListPath")
            .or_else(|| response.get("NewHostListPath"))
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                ClientError::Transport("tr064: GetHostListPath returned empty path".to_owned())
            })?;
        let url = absolute_path(self.base_url(), path)?;
        let response = self.authenticated_get(&url)?;
        parse_host_list(&response.body)
            .map_err(|error| ClientError::Transport(format!("parsing host list: {error}")))
    }

    fn hosts_from_index(&mut self) -> Result<Vec<Host>, ClientError> {
        let count = self.call(
            &Service::hosts(),
            "GetHostNumberOfEntries",
            &BTreeMap::new(),
        )?;
        let count = count
            .get("NewHostNumberOfEntries")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut hosts = Vec::with_capacity(count);
        for index in 0..count {
            let args = BTreeMap::from([(String::from("NewIndex"), index.to_string())]);
            if let Ok(entry) = self.call(&Service::hosts(), "GetGenericHostEntry", &args) {
                hosts.push(Host::from_entry(&entry));
            }
        }
        Ok(hosts)
    }

    /// Return only active entries, preserving table order.
    pub fn active_hosts(&mut self) -> Result<Vec<Host>, ClientError> {
        Ok(self
            .hosts()?
            .into_iter()
            .filter(|host| host.active)
            .collect())
    }

    /// Look up one host through the Hosts service's MAC index.
    pub fn host_by_mac(&mut self, mac: &str) -> Result<Host, ClientError> {
        let args = BTreeMap::from([(String::from("NewMACAddress"), mac.to_ascii_uppercase())]);
        let mut host =
            Host::from_entry(&self.call(&Service::hosts(), "GetSpecificHostEntry", &args)?);
        host.mac = mac.to_ascii_uppercase();
        Ok(host)
    }

    /// Look up one host through AVM's IP extension.
    pub fn host_by_ip(&mut self, ip: &str) -> Result<Host, ClientError> {
        let args = BTreeMap::from([(String::from("NewIPAddress"), ip.to_owned())]);
        let mut host = Host::from_entry(&self.call(
            &Service::hosts(),
            "X_AVM-DE_GetSpecificHostEntryByIP",
            &args,
        )?);
        host.ip = ip.to_owned();
        Ok(host)
    }

    /// Resolve a case-insensitive host-table name; duplicate names are rejected.
    pub fn host_by_name(&mut self, name: &str) -> Result<Host, ClientError> {
        let matches: Vec<_> = self
            .hosts()?
            .into_iter()
            .filter(|host| host.name.eq_ignore_ascii_case(name))
            .collect();
        match matches.as_slice() {
            [] => Err(ClientError::Transport(format!(
                "no host named {name:?} in the FRITZ!Box host table"
            ))),
            [host] => Ok(host.clone()),
            many => Err(ClientError::Transport(format!(
                "{} hosts named {name:?}; use --mac or --ip to disambiguate",
                many.len()
            ))),
        }
    }

    /// Resolve a name, MAC, or IP according to the Go client's detection rules.
    pub fn resolve_host(&mut self, reference: &str) -> Result<Host, ClientError> {
        if looks_like_ip(reference) {
            self.host_by_ip(reference)
        } else if looks_like_mac(reference) {
            self.host_by_mac(reference)
        } else {
            self.host_by_name(reference)
        }
    }

    /// Send a Wake-on-LAN magic-packet request through the box.
    pub fn wake_on_lan(&mut self, mac: &str) -> Result<(), ClientError> {
        let args = BTreeMap::from([(String::from("NewMACAddress"), mac.to_ascii_uppercase())]);
        self.call(&Service::hosts(), "X_AVM-DE_WakeOnLANByMACAddress", &args)
            .map(|_| ())
    }

    /// Probe WLAN configuration services in ascending index order.
    pub fn radios(&mut self, max_n: usize) -> Result<Vec<Radio>, ClientError> {
        let max_n = if max_n == 0 { 3 } else { max_n };
        let mut radios = Vec::new();
        for index in 1..=max_n {
            match self.call(&wlan_service(index), "GetInfo", &BTreeMap::new()) {
                Ok(info) => radios.push(Radio::from_info(index, &info)),
                Err(error) if index == 1 || is_unauthorized(&error) || is_transport(&error) => {
                    return Err(error);
                }
                Err(_) => break,
            }
        }
        if radios.is_empty() {
            return Err(ClientError::Transport(
                "wlan: no WLANConfiguration service responded".to_owned(),
            ));
        }
        Ok(radios)
    }

    /// Return associated clients for one radio, preserving association index order.
    pub fn wlan_clients(&mut self, index: usize) -> Result<Vec<WlanClient>, ClientError> {
        let service = wlan_service(index);
        let total = self.call(&service, "GetTotalAssociations", &BTreeMap::new())?;
        let total = total
            .get("NewTotalAssociations")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut clients = Vec::with_capacity(total);
        for associated_index in 0..total {
            let args = BTreeMap::from([(
                String::from("NewAssociatedDeviceIndex"),
                associated_index.to_string(),
            )]);
            if let Ok(info) = self.call(&service, "GetGenericAssociatedDeviceInfo", &args) {
                clients.push(WlanClient {
                    radio_index: index,
                    mac: info
                        .get("NewAssociatedDeviceMACAddress")
                        .cloned()
                        .unwrap_or_default(),
                    ip: info
                        .get("NewAssociatedDeviceIPAddress")
                        .cloned()
                        .unwrap_or_default(),
                    signal: info
                        .get("NewX_AVM-DE_SignalStrength")
                        .cloned()
                        .unwrap_or_default(),
                    speed: info.get("NewX_AVM-DE_Speed").cloned().unwrap_or_default(),
                    authorized: info
                        .get("NewAssociatedDeviceAuthState")
                        .is_some_and(|value| value == "1"),
                });
            }
        }
        Ok(clients)
    }

    /// Aggregate clients in radio order. Individual radio failures are skipped.
    pub fn all_wlan_clients(&mut self, max_n: usize) -> Result<Vec<WlanClient>, ClientError> {
        let radios = self.radios(max_n)?;
        let mut clients = Vec::new();
        for radio in radios {
            if let Ok(mut radio_clients) = self.wlan_clients(radio.index) {
                clients.append(&mut radio_clients);
            }
        }
        Ok(clients)
    }

    /// Read the explicitly selected guest WLAN configuration.
    pub fn guest_wlan_status(&mut self, guest_index: usize) -> Result<Radio, ClientError> {
        let info = self.call(&wlan_service(guest_index), "GetInfo", &BTreeMap::new())?;
        Ok(Radio::from_info(guest_index, &info))
    }

    /// Enable or disable the explicitly selected guest WLAN configuration.
    pub fn set_guest_wlan(&mut self, guest_index: usize, enable: bool) -> Result<(), ClientError> {
        let args = BTreeMap::from([(
            String::from("NewEnable"),
            if enable { "1" } else { "0" }.to_owned(),
        )]);
        self.call(&wlan_service(guest_index), "SetEnable", &args)
            .map(|_| ())
    }

    /// Fetch and parse the mesh topology JSON returned by the Hosts extension.
    pub fn mesh_topology(&mut self) -> Result<MeshTopology, ClientError> {
        let response = self.call(
            &Service::hosts(),
            "X_AVM-DE_GetMeshListPath",
            &BTreeMap::new(),
        )?;
        let path = response
            .get("NewX_AVM-DE_MeshListPath")
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                ClientError::Transport(
                    "box returned no mesh list path (unsupported firmware?)".to_owned(),
                )
            })?;
        let url = absolute_path(self.base_url(), path)?;
        let response = self.authenticated_get_with_limit(&url, MESH_RESPONSE_LIMIT)?;
        serde_json::from_slice(&response.body).map_err(|error| {
            ClientError::Transport(format!("mesh: parsing mesh list JSON: {error}"))
        })
    }
}

fn is_transport(error: &ClientError) -> bool {
    matches!(error_kind(error), ErrorKind::Transport | ErrorKind::Timeout)
}

impl StatusError {
    fn from_error(service: &str, action: &str, error: &ClientError) -> Self {
        Self {
            service: service.to_owned(),
            action: action.to_owned(),
            message: error.to_string(),
            kind: error_kind(error),
        }
    }
}

/// Host table entry returned by the Hosts service.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Host {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub active: bool,
    pub interface_type: String,
    pub address_source: String,
    pub lease_time_remaining: i64,
}

impl Host {
    fn from_entry(entry: &BTreeMap<String, String>) -> Self {
        Self {
            name: entry.get("NewHostName").cloned().unwrap_or_default(),
            ip: entry.get("NewIPAddress").cloned().unwrap_or_default(),
            mac: entry
                .get("NewMACAddress")
                .map_or_else(String::new, |mac| mac.to_ascii_uppercase()),
            active: entry.get("NewActive").is_some_and(|value| value == "1"),
            interface_type: entry.get("NewInterfaceType").cloned().unwrap_or_default(),
            address_source: entry.get("NewAddressSource").cloned().unwrap_or_default(),
            lease_time_remaining: entry
                .get("NewLeaseTimeRemaining")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        }
    }

    /// Human-readable connection medium.
    #[must_use]
    pub fn link(&self) -> &str {
        if self.interface_type.starts_with("802.11") {
            "WLAN"
        } else if self.interface_type == "Ethernet" {
            "LAN"
        } else if self.interface_type.is_empty() {
            "—"
        } else {
            &self.interface_type
        }
    }
}

/// Compatibility alias retaining the Go acronym spelling.
pub type WLANHost = Host;

fn parse_host_list(xml: &[u8]) -> Result<Vec<Host>, String> {
    let input = str::from_utf8(xml).map_err(|error| error.to_string())?;
    let document = Document::parse(input).map_err(|error| error.to_string())?;
    let mut hosts = Vec::new();
    for item in document
        .descendants()
        .filter(|node| node.has_tag_name("Item"))
    {
        let text = |name: &str| {
            item.children()
                .find(|child| child.has_tag_name(name))
                .and_then(|child| child.text())
                .unwrap_or_default()
                .to_owned()
        };
        let entry = BTreeMap::from([
            (String::from("NewHostName"), text("HostName")),
            (String::from("NewIPAddress"), text("IPAddress")),
            (String::from("NewMACAddress"), text("MACAddress")),
            (String::from("NewActive"), text("Active")),
            (String::from("NewInterfaceType"), text("InterfaceType")),
            (String::from("NewAddressSource"), text("AddressSource")),
            (
                String::from("NewLeaseTimeRemaining"),
                text("LeaseTimeRemaining"),
            ),
        ]);
        hosts.push(Host::from_entry(&entry));
    }
    Ok(hosts)
}

/// State of one WLAN radio.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Radio {
    pub index: usize,
    pub ssid: String,
    pub enabled: bool,
    pub channel: String,
    pub standard: String,
    pub bssid: String,
    pub status: String,
}

impl Radio {
    fn from_info(index: usize, info: &BTreeMap<String, String>) -> Self {
        Self {
            index,
            ssid: info.get("NewSSID").cloned().unwrap_or_default(),
            enabled: info.get("NewEnable").is_some_and(|value| value == "1"),
            channel: info.get("NewChannel").cloned().unwrap_or_default(),
            standard: info.get("NewStandard").cloned().unwrap_or_default(),
            bssid: info.get("NewBSSID").cloned().unwrap_or_default(),
            status: info.get("NewStatus").cloned().unwrap_or_default(),
        }
    }
}

/// A device associated with a WLAN radio.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WlanClient {
    pub radio_index: usize,
    pub mac: String,
    pub ip: String,
    #[serde(rename = "signal_strength", skip_serializing_if = "String::is_empty")]
    pub signal: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub speed: String,
    pub authorized: bool,
}

/// Compatibility alias retaining the Go acronym spelling.
pub type WLANClient = WlanClient;

/// Parsed mesh topology.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshTopology {
    pub schema_version: String,
    pub nodes: Vec<MeshNode>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshNode {
    pub uid: String,
    pub device_name: String,
    pub device_model: String,
    pub is_meshed: bool,
    pub mesh_role: String,
    pub node_interfaces: Vec<MeshInterface>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshInterface {
    pub uid: String,
    pub name: String,
    #[serde(rename = "type")]
    pub interface_type: String,
    pub node_links: Vec<MeshLink>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshLink {
    pub state: String,
    pub node_1: String,
    pub node_2: String,
    pub max_data_rate_rx: i64,
    pub max_data_rate_tx: i64,
    pub cur_data_rate_rx: i64,
    pub cur_data_rate_tx: i64,
}

impl MeshTopology {
    /// Resolve a node or interface UID to its parent device name.
    #[must_use]
    pub fn node_name(&self, uid: &str) -> String {
        self.nodes
            .iter()
            .find(|node| {
                node.uid == uid
                    || node
                        .node_interfaces
                        .iter()
                        .any(|interface| interface.uid == uid)
            })
            .map_or_else(|| uid.to_owned(), |node| node.device_name.clone())
    }
}

fn wlan_service(index: usize) -> Service {
    Service {
        service_type: format!("urn:dslforum-org:service:WLANConfiguration:{index}"),
        control_url: format!("/upnp/control/wlanconfig{index}"),
    }
}

fn absolute_path(base: &str, path: &str) -> Result<String, ClientError> {
    if url::Url::parse(path).is_ok_and(|url| url.scheme() == "http" || url.scheme() == "https") {
        return Ok(path.to_owned());
    }
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    Ok(format!("{}{}", base.trim_end_matches('/'), path))
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

fn looks_like_mac(value: &str) -> bool {
    value.matches(':').count() == 5 || value.matches('-').count() == 5
}

impl Service {
    fn device_info() -> Self {
        Self {
            service_type: String::from("urn:dslforum-org:service:DeviceInfo:1"),
            control_url: String::from("/upnp/control/deviceinfo"),
        }
    }
    fn user_interface() -> Self {
        Self {
            service_type: String::from("urn:dslforum-org:service:UserInterface:1"),
            control_url: String::from("/upnp/control/userif"),
        }
    }
    fn wan_ip_connection() -> Self {
        Self {
            service_type: String::from("urn:dslforum-org:service:WANIPConnection:1"),
            control_url: String::from("/upnp/control/wanipconnection1"),
        }
    }
    fn wan_ppp_connection() -> Self {
        Self {
            service_type: String::from("urn:dslforum-org:service:WANPPPConnection:1"),
            control_url: String::from("/upnp/control/wanpppconn1"),
        }
    }
    fn hosts() -> Self {
        Self {
            service_type: String::from("urn:dslforum-org:service:Hosts:1"),
            control_url: String::from("/upnp/control/hosts"),
        }
    }
}

/// Whether an IP is RFC1918/ULA or link-local, matching Go's `IsPrivateIP`.
#[must_use]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[must_use]
pub fn all_public(ips: &[String]) -> bool {
    ips.iter()
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .all(|ip| !is_private_ip(ip))
}

/// Result of resolving a host and comparing it with the default gateway.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolveHostInfo {
    pub ips: Vec<String>,
    pub is_public: bool,
    pub is_gateway: bool,
}

#[must_use]
pub fn classify_resolved_host(ips: &[String], gateway: Option<IpAddr>) -> ResolveHostInfo {
    ResolveHostInfo {
        ips: ips.to_vec(),
        is_public: all_public(ips),
        is_gateway: gateway.is_some_and(|gateway| {
            ips.iter()
                .any(|ip| ip.parse::<IpAddr>().is_ok_and(|ip| ip == gateway))
        }),
    }
}

/// Parse the first Linux `default via <ip>` route.
#[must_use]
pub fn parse_linux_default_gateway(output: &str) -> Option<IpAddr> {
    let fields: Vec<_> = output.split_whitespace().collect();
    fields
        .windows(2)
        .find(|pair| pair[0] == "via")
        .and_then(|pair| pair[1].parse().ok())
}

/// Parse the first Windows `0.0.0.0 0.0.0.0 <gateway>` route.
#[must_use]
pub fn parse_windows_default_gateway(output: &str) -> Option<IpAddr> {
    output.lines().map(str::trim).find_map(|line| {
        if !line.starts_with("0.0.0.0") {
            return None;
        }
        line.split_whitespace().nth(2)?.parse().ok()
    })
}

/// Probe a TR-064 description through the injected transport.
pub fn probe_tr064<T: Transport>(
    transport: &mut T,
    ip: IpAddr,
    port: u16,
    _insecure_tls: bool,
) -> bool {
    let scheme = if port == 49443 { "https" } else { "http" };
    let request = Request {
        method: Method::Get,
        url: format!("{scheme}://{ip}:{port}/tr64desc.xml"),
        headers: BTreeMap::new(),
        body: Vec::new(),
        response_limit: 4096,
    };
    let Ok(response) = transport.send(request) else {
        return false;
    };
    response.status == 200
        && (response
            .body
            .windows(b"urn:schemas-upnp-org:device-1-0".len())
            .any(|window| window == b"urn:schemas-upnp-org:device-1-0")
            || response
                .body
                .windows(b"urn:dslforum-org:device-1-0".len())
                .any(|window| window == b"urn:dslforum-org:device-1-0"))
}

/// One diagnosis status.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Fail,
    Warn,
    #[default]
    Skip,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Diagnosis {
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<Host>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    pub checks: Vec<Check>,
    pub ok: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortProbe {
    pub port: u16,
    pub label: String,
    #[serde(rename = "type")]
    pub probe_type: String,
    pub optional: bool,
}

impl Default for PortProbe {
    fn default() -> Self {
        Self {
            port: 0,
            label: String::new(),
            probe_type: String::from("tcp"),
            optional: false,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnoseOptions {
    pub ports: Vec<PortProbe>,
    pub dial_timeout_ms: u64,
}

pub fn default_probes() -> Vec<PortProbe> {
    vec![
        PortProbe {
            port: 22,
            label: String::from("SSH"),
            probe_type: String::from("ssh"),
            optional: false,
        },
        PortProbe {
            port: 5900,
            label: String::from("VNC/Screen Sharing"),
            probe_type: String::from("tcp"),
            optional: false,
        },
        PortProbe {
            port: 8001,
            label: String::from("Paperless"),
            probe_type: String::from("tcp"),
            optional: false,
        },
    ]
}

impl<T: Transport, C: CnonceSource> Client<T, C> {
    /// Diagnose a name, MAC, or IP. Port worker count is capped and output stays
    /// in input order regardless of probe completion order.
    pub fn diagnose(&mut self, reference: &str, options: DiagnoseOptions) -> Diagnosis {
        let mut options = options;
        if options.ports.is_empty() {
            options.ports = default_probes();
        }
        let timeout = if options.dial_timeout_ms == 0 {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(options.dial_timeout_ms)
        };
        let mut diagnosis = Diagnosis {
            reference: reference.to_owned(),
            ok: true,
            ..Diagnosis::default()
        };
        match self.resolve_host(reference) {
            Ok(host) => {
                diagnosis.target = host.ip.clone();
                diagnosis.host = Some(host.clone());
                diagnosis.add("FRITZ!Box knows host", CheckStatus::Ok, &host.name);
                diagnosis.add(
                    "Host active",
                    if host.active {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Warn
                    },
                    if host.active {
                        ""
                    } else {
                        "box reports host as inactive"
                    },
                );
                if host.ip.is_empty() {
                    diagnosis.add("IP address", CheckStatus::Warn, "no IP in host table");
                } else {
                    diagnosis.add("IP address", CheckStatus::Ok, &host.ip);
                }
                diagnosis.add(
                    "Link medium",
                    if host.link() == "—" {
                        CheckStatus::Warn
                    } else {
                        CheckStatus::Ok
                    },
                    host.link(),
                );
            }
            Err(error) => {
                diagnosis.add(
                    "FRITZ!Box knows host",
                    CheckStatus::Fail,
                    &error.to_string(),
                );
                if looks_like_ip(reference) {
                    diagnosis.target = reference.to_owned();
                }
            }
        }
        if !looks_like_ip(reference) && !looks_like_mac(reference) {
            let addresses: Vec<String> = (reference, 0)
                .to_socket_addrs()
                .map(|addresses| addresses.map(|address| address.ip().to_string()).collect())
                .unwrap_or_default();
            if addresses.is_empty() {
                diagnosis.add(
                    "DNS resolves",
                    CheckStatus::Warn,
                    "name does not resolve via system DNS",
                );
            } else {
                let mut addresses = addresses;
                addresses.sort();
                addresses.dedup();
                let detail = addresses
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                diagnosis.add("DNS resolves", CheckStatus::Ok, &detail);
                if diagnosis.target.is_empty() {
                    diagnosis.target = addresses[0].clone();
                }
            }
        }
        if diagnosis.target.is_empty() {
            diagnosis.add(
                "TCP reachability",
                CheckStatus::Skip,
                "no target IP to probe",
            );
            diagnosis.finalize();
            return diagnosis;
        }
        for result in probe_ports(&diagnosis.target, &options.ports, timeout) {
            diagnosis.add(&result.name, result.status, &result.detail);
        }
        diagnosis.finalize();
        diagnosis
    }
}

impl Diagnosis {
    fn add(&mut self, name: &str, status: CheckStatus, detail: &str) {
        self.checks.push(Check {
            name: name.to_owned(),
            status,
            detail: detail.to_owned(),
        });
    }
    fn finalize(&mut self) {
        self.ok = !self
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail);
    }
}

struct ProbeResult {
    name: String,
    status: CheckStatus,
    detail: String,
}

fn probe_ports(target: &str, probes: &[PortProbe], timeout: Duration) -> Vec<ProbeResult> {
    let mut results = Vec::with_capacity(probes.len());
    for chunk in probes.chunks(MAX_DIAGNOSIS_WORKERS) {
        let joined: Vec<_> = thread::scope(|scope| {
            chunk
                .iter()
                .map(|probe| scope.spawn(|| probe_port(target, probe, timeout)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| {
                    handle.join().unwrap_or_else(|_| ProbeResult {
                        name: String::new(),
                        status: CheckStatus::Fail,
                        detail: String::from("probe worker failed"),
                    })
                })
                .collect()
        });
        results.extend(joined);
    }
    results
}

fn probe_port(target: &str, probe: &PortProbe, timeout: Duration) -> ProbeResult {
    let probe_type = if probe.probe_type.is_empty() {
        "tcp"
    } else {
        &probe.probe_type
    };
    let name = format!(
        "{} {} ({})",
        probe_type.to_ascii_uppercase(),
        probe.port,
        probe.label
    );
    let failure = if probe.optional {
        CheckStatus::Warn
    } else {
        CheckStatus::Fail
    };
    if probe_type == "ssh" {
        if dial_ssh(target, probe.port, timeout) {
            ProbeResult {
                name,
                status: CheckStatus::Ok,
                detail: String::from("ssh handshake ok"),
            }
        } else {
            ProbeResult {
                name,
                status: failure,
                detail: String::from("closed or no ssh banner"),
            }
        }
    } else if dial_tcp(target, probe.port, timeout) {
        ProbeResult {
            name,
            status: CheckStatus::Ok,
            detail: String::from("open"),
        }
    } else {
        ProbeResult {
            name,
            status: failure,
            detail: String::from("closed or filtered"),
        }
    }
}

/// Test a TCP port with a bounded connect timeout.
#[must_use]
pub fn dial_tcp(target: &str, port: u16, timeout: Duration) -> bool {
    let Ok(ip) = target.parse::<IpAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout).is_ok()
}

/// Test a TCP port and require an SSH protocol banner.
#[must_use]
pub fn dial_ssh(target: &str, port: u16, timeout: Duration) -> bool {
    let Ok(ip) = target.parse::<IpAddr>() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout) else {
        return false;
    };
    if stream.set_read_timeout(Some(timeout)).is_err() {
        return false;
    }
    let mut buffer = [0_u8; 255];
    let Ok(size) = stream.read(&mut buffer) else {
        return false;
    };
    buffer[..size].starts_with(b"SSH-")
}

#[cfg(test)]
mod tests {
    use super::{
        all_public, classify_resolved_host, is_private_ip, parse_linux_default_gateway,
        parse_windows_default_gateway,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn router_classification_matches_go() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(all_public(&[String::from("127.0.0.1")]));
        assert!(
            classify_resolved_host(&[String::from("8.8.8.8")], Some("8.8.8.8".parse().unwrap()))
                .is_gateway
        );
    }

    #[test]
    fn gateway_parsers_accept_expected_routes() {
        assert_eq!(
            parse_linux_default_gateway("default via 192.168.178.1 dev en0"),
            Some("192.168.178.1".parse().unwrap())
        );
        assert_eq!(
            parse_windows_default_gateway("0.0.0.0 0.0.0.0 192.168.178.1 25"),
            Some("192.168.178.1".parse().unwrap())
        );
    }
}
