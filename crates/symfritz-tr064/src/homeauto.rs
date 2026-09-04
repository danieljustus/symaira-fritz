use std::collections::BTreeMap;

use crate::{Client, ClientError, Service};

/// The fixed TR-064 service used by FRITZ!OS Homeauto.
pub fn homeauto_service() -> Service {
    Service {
        service_type: "urn:dslforum-org:service:X_AVM-DE_Homeauto:1".to_owned(),
        control_url: "/upnp/control/x_homeauto".to_owned(),
    }
}

/// One smart-home device returned by `GetGenericDeviceInfos`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HomeautoDevice {
    pub ain: String,
    pub function_bit_mask: i32,
    pub manufacturer: String,
    pub product_name: String,
    pub firmware_version: String,
}

impl HomeautoDevice {
    #[must_use]
    pub fn is_switch(&self) -> bool {
        self.function_bit_mask & (1 << 15) != 0
    }

    #[must_use]
    pub fn is_thermostat(&self) -> bool {
        self.function_bit_mask & (1 << 6) != 0
    }

    #[must_use]
    pub fn is_bulb(&self) -> bool {
        self.function_bit_mask & (1 << 2) != 0
    }

    #[must_use]
    pub fn is_alarm_sensor(&self) -> bool {
        self.function_bit_mask & (1 << 4) != 0
    }

    #[must_use]
    pub fn is_button(&self) -> bool {
        self.function_bit_mask & (1 << 5) != 0
    }

    #[must_use]
    pub fn is_blind(&self) -> bool {
        self.function_bit_mask & (1 << 18) != 0
    }

    #[must_use]
    pub fn is_energy_sensor(&self) -> bool {
        self.function_bit_mask & (1 << 7) != 0
    }

    #[must_use]
    pub fn is_temperature_sensor(&self) -> bool {
        self.function_bit_mask & (1 << 8) != 0
    }
}

impl<T: crate::Transport, C: crate::CnonceSource> Client<T, C> {
    /// Enumerate Homeauto devices until the first TR-064 error.
    ///
    /// Go's current contract treats every call error as end-of-list and returns
    /// the devices accumulated so far without surfacing that error.
    pub fn homeauto_devices(&mut self) -> Result<Vec<HomeautoDevice>, ClientError> {
        let mut devices = Vec::new();
        for index in 0.. {
            let arguments = BTreeMap::from([(String::from("NewIndex"), index.to_string())]);
            let result = match self.call(&homeauto_service(), "GetGenericDeviceInfos", &arguments) {
                Ok(result) => result,
                Err(_) => break,
            };
            let function_bit_mask = result
                .get("NewFunctionBitMask")
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or_default();
            devices.push(HomeautoDevice {
                ain: result.get("NewAIN").cloned().unwrap_or_default(),
                function_bit_mask,
                manufacturer: result.get("NewManufacturer").cloned().unwrap_or_default(),
                product_name: result.get("NewProductName").cloned().unwrap_or_default(),
                firmware_version: result
                    .get("NewFirmwareVersion")
                    .cloned()
                    .unwrap_or_default(),
            });
        }
        Ok(devices)
    }

    /// Set one Homeauto actor's switch state to the exact Go `ON`/`OFF` value.
    pub fn homeauto_switch(&mut self, ain: &str, on: bool) -> Result<(), ClientError> {
        let arguments = BTreeMap::from([
            (String::from("NewAIN"), ain.to_owned()),
            (
                String::from("NewSwitchState"),
                if on {
                    "ON".to_owned()
                } else {
                    "OFF".to_owned()
                },
            ),
        ]);
        self.call(&homeauto_service(), "SetSwitch", &arguments)
            .map(|_| ())
    }
}
