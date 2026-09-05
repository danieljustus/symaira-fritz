use serde_json::{Value, json};
use symfritz_mcp::{Capabilities, Server};

struct Fixture;

impl Capabilities for Fixture {
    fn status(&mut self) -> Result<Value, String> {
        Ok(Value::String(
            "{\n  \"ModelName\": \"FRITZ!Box 7590\",\n  \"FirmwareVersion\": \"7.57\",\n  \"ExternalIP\": \"203.0.113.1\",\n  \"ConnectionState\": \"Connected\",\n  \"Uptime\": \"3600\",\n  \"UpdateAvailable\": \"\",\n  \"Partial\": false,\n  \"Errors\": null\n}"
                .to_owned(),
        ))
    }

    fn host_list(&mut self, _active_only: bool) -> Result<Value, String> {
        Ok(json!({"hosts": []}))
    }

    fn host_get(
        &mut self,
        name: Option<&str>,
        mac: Option<&str>,
        ip: Option<&str>,
    ) -> Result<Value, String> {
        if name.is_none() && mac.is_none() && ip.is_none() {
            return Err("provide one of name, mac, or ip".to_owned());
        }
        Ok(json!({"name": name, "mac": mac, "ip": ip}))
    }

    fn diagnose(&mut self, _host: &str, _ports: &[i64]) -> Result<Value, String> {
        Ok(json!({"ok": true}))
    }

    fn mesh(&mut self) -> Result<Value, String> {
        Ok(json!({"nodes": []}))
    }

    fn wlan_clients(&mut self) -> Result<Value, String> {
        Ok(json!([]))
    }

    fn wake_on_lan(&mut self, host: Option<&str>, mac: Option<&str>) -> Result<Value, String> {
        if host.is_none() && mac.is_none() {
            return Err("provide host or mac".to_owned());
        }
        Ok(json!({"woke": mac.unwrap_or_default()}))
    }

    fn home_list(&mut self) -> Result<Value, String> {
        Ok(json!([]))
    }

    fn home_switch(&mut self, ain: &str, on: bool) -> Result<Value, String> {
        Ok(json!({"ain": ain, "on": on}))
    }
}

fn main() -> std::io::Result<()> {
    Server::new("symfritz", "dev", Fixture).serve_stdio()
}
