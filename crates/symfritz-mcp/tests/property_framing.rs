#![deny(unsafe_code)]

use std::io::Cursor;

use proptest::prelude::*;
use serde_json::{Value, json};
use symfritz_mcp::{Capabilities, Server};

struct Noop;

impl Capabilities for Noop {
    fn status(&mut self) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn host_list(&mut self, _: bool) -> Result<Value, String> {
        Ok(json!([]))
    }
    fn host_get(
        &mut self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn diagnose(&mut self, _: &str, _: &[i64]) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn mesh(&mut self) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn wlan_clients(&mut self) -> Result<Value, String> {
        Ok(json!([]))
    }
    fn wake_on_lan(&mut self, _: Option<&str>, _: Option<&str>) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn home_list(&mut self) -> Result<Value, String> {
        Ok(json!([]))
    }
    fn home_switch(&mut self, _: &str, _: bool) -> Result<Value, String> {
        Ok(json!({}))
    }
}

proptest! {
    #[test]
    fn mcp_framing_accepts_arbitrary_input_without_panicking(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        let result = std::panic::catch_unwind(|| {
            let mut output = Vec::new();
            let _ = Server::new("symfritz", "test", Noop).serve_io(Cursor::new(input), &mut output);
        });
        prop_assert!(result.is_ok());
    }
}
