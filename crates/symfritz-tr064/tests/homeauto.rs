use std::collections::VecDeque;

use symfritz_tr064::{
    Client, CnonceSource, HomeautoDevice, Method, Request, Response, Transport, TransportError,
};

#[derive(Default)]
struct FakeTransport {
    responses: VecDeque<Response>,
    requests: Vec<Request>,
}

impl Transport for FakeTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .ok_or_else(|| TransportError("end of list".to_owned()))
    }
}

#[derive(Default)]
struct NoCnonce;

impl CnonceSource for NoCnonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        Err("unexpected digest challenge".to_owned())
    }
}

fn soap_response(action: &str, fields: &[(&str, &str)]) -> Response {
    let values = fields
        .iter()
        .map(|(name, value)| format!("<{name}>{value}</{name}>"))
        .collect::<String>();
    Response {
        status: 200,
        body: format!(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"urn:dslforum-org:service:X_AVM-DE_Homeauto:1\">{values}</u:{action}Response></s:Body></s:Envelope>"
        )
        .into_bytes(),
        ..Response::default()
    }
}

fn client(responses: impl IntoIterator<Item = Response>) -> Client<FakeTransport, NoCnonce> {
    Client::new(
        FakeTransport {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        },
        NoCnonce,
        "http://fritz.box:49000",
        "admin",
        "secret",
    )
}

#[test]
fn homeauto_enumeration_maps_fields_until_first_error() {
    let mut client = client([soap_response(
        "GetGenericDeviceInfos",
        &[
            ("NewAIN", "12345"),
            ("NewFunctionBitMask", "262208"),
            ("NewManufacturer", "AVM"),
            ("NewProductName", "DECT 200"),
            ("NewFirmwareVersion", "1.2.3"),
        ],
    )]);
    let devices = client.homeauto_devices().unwrap();
    assert_eq!(
        devices,
        [HomeautoDevice {
            ain: "12345".to_owned(),
            function_bit_mask: 262208,
            manufacturer: "AVM".to_owned(),
            product_name: "DECT 200".to_owned(),
            firmware_version: "1.2.3".to_owned(),
        }]
    );
    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 2);
    assert_eq!(transport.requests[0].method, Method::Post);
    assert_eq!(
        transport.requests[0].url,
        "http://fritz.box:49000/upnp/control/x_homeauto"
    );
    assert!(
        transport.requests[0]
            .body
            .windows(b"<NewIndex>0</NewIndex>".len())
            .any(|window| window == b"<NewIndex>0</NewIndex>")
    );
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:X_AVM-DE_Homeauto:1#GetGenericDeviceInfos"
    );
}

#[test]
fn homeauto_capability_bits_and_switch_arguments_match_go() {
    let mask =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 15) | (1 << 18);
    let device = HomeautoDevice {
        function_bit_mask: mask,
        ..HomeautoDevice::default()
    };
    assert!(device.is_switch());
    assert!(device.is_thermostat());
    assert!(device.is_bulb());
    assert!(device.is_alarm_sensor());
    assert!(device.is_button());
    assert!(device.is_blind());
    assert!(device.is_energy_sensor());
    assert!(device.is_temperature_sensor());

    let mut client = client([
        soap_response("SetSwitch", &[]),
        soap_response("SetSwitch", &[]),
    ]);
    client.homeauto_switch("ain-on", true).unwrap();
    client.homeauto_switch("ain-off", false).unwrap();
    let transport = client.into_transport();
    assert!(
        String::from_utf8_lossy(&transport.requests[0].body).contains("<NewAIN>ain-on</NewAIN>")
    );
    assert!(
        String::from_utf8_lossy(&transport.requests[0].body)
            .contains("<NewSwitchState>ON</NewSwitchState>")
    );
    assert!(
        String::from_utf8_lossy(&transport.requests[1].body)
            .contains("<NewSwitchState>OFF</NewSwitchState>")
    );
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:X_AVM-DE_Homeauto:1#SetSwitch"
    );
}
