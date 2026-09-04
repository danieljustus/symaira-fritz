#![deny(unsafe_code)]

//! SOAP/TR-064 protocol engine for the staged Rust port.

mod client;
mod discovery;
mod soap;

pub use client::{
    Client, ClientError, CnonceSource, Method, Request, Response, Transport, TransportError,
};
pub use discovery::{DiscoveryError, Service, find_service_by_name, parse_description};
pub use soap::{SoapParseError, build_request, parse_fault, parse_response};
