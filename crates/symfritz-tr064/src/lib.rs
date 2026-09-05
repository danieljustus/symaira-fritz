#![deny(unsafe_code)]

//! SOAP/TR-064 protocol engine for the staged Rust port.

mod capabilities;
mod client;
mod discovery;
mod homeauto;
mod safeurl;
mod soap;
mod transport;

pub use capabilities::{
    CALL_ALL, CALL_INCOMING, CALL_MISSED, CALL_OUTGOING, CALL_REJECTED, Call, Check, CheckStatus,
    DiagnoseOptions, Diagnosis, DslLineStats, ErrorKind, Host, LogEvent, MESH_RESPONSE_LIMIT,
    MeshInterface, MeshLink, MeshNode, MeshTopology, PortProbe, Radio, ResolveHostInfo, Status,
    StatusError, StatusFailure, TrafficData, WLANClient, WLANHost, WlanClient, all_public,
    classify_resolved_host, default_probes, dial_ssh, dial_tcp, error_kind, is_private_ip,
    parse_linux_default_gateway, parse_mesh_topology, parse_windows_default_gateway, probe_tr064,
};
pub use client::{
    Client, ClientError, CnonceSource, Method, Request, Response, Transport, TransportError,
};
pub use discovery::{DiscoveryError, Service, find_service_by_name, parse_description};
pub use homeauto::{HomeautoDevice, homeauto_service};
pub use safeurl::{
    SafeUrlError, redact_error_message, redact_raw_url, redact_url, validate_request_url,
};
pub use soap::{SoapParseError, build_request, parse_fault, parse_response};
pub use transport::{
    BlockingHttpTransport, DEFAULT_RESPONSE_LIMIT, HttpTransportConfig, HttpTransportError,
    endpoint_unreachable_message,
};
