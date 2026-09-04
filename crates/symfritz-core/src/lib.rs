#![deny(unsafe_code)]

//! Pure domain and protocol primitives for the Rust port.

pub mod auth;
pub mod config;
pub mod pins;
pub mod secret;

pub use pins::{PinStore, PinStoreError, calculate_spki_pin};
