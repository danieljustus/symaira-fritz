use roxmltree::Document;

/// A TR-064 service endpoint advertised by `tr64desc.xml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub service_type: String,
    pub control_url: String,
}

/// Discovery XML or service-selection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryError(pub String);

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DiscoveryError {}

/// Parse every service nested under a device and sort by service type.
///
/// ```
/// use symfritz_tr064::parse_description;
///
/// let xml = b"<root><device><serviceList><service><serviceType>urn:test:service:Info:1</serviceType><controlURL>/info</controlURL></service></serviceList></device></root>";
/// let services = parse_description(xml).unwrap();
/// assert_eq!(services[0].control_url, "/info");
/// ```
pub fn parse_description(xml: &[u8]) -> Result<Vec<Service>, DiscoveryError> {
    let input = std::str::from_utf8(xml)
        .map_err(|error| DiscoveryError(format!("discover: parsing tr64desc.xml: {error}")))?;
    let document = Document::parse(input)
        .map_err(|error| DiscoveryError(format!("discover: parsing tr64desc.xml: {error}")))?;

    let mut services = Vec::new();
    for service in document.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "service"
            && node
                .parent_element()
                .is_some_and(|parent| parent.tag_name().name() == "serviceList")
            && node
                .parent_element()
                .and_then(|parent| parent.parent_element())
                .is_some_and(|parent| parent.tag_name().name() == "device")
    }) {
        let service_type = child_text(service, "serviceType");
        let control_url = child_text(service, "controlURL");
        services.push(Service {
            service_type,
            control_url,
        });
    }
    services.sort_by(|left, right| left.service_type.cmp(&right.service_type));
    Ok(services)
}

/// Resolve a discovered service using the Go implementation's matching rules.
pub fn find_service_by_name(services: &[Service], name: &str) -> Result<Service, DiscoveryError> {
    let lowercase_name = name.to_lowercase();
    let matches: Vec<_> = services
        .iter()
        .filter(|service| {
            service
                .service_type
                .to_lowercase()
                .contains(&lowercase_name)
        })
        .collect();
    match matches.as_slice() {
        [] => Err(DiscoveryError(format!(
            "no discovered service matches \"{name}\""
        ))),
        [service] => Ok((*service).clone()),
        many => {
            let exact = format!(":{lowercase_name}:");
            if let Some(service) = many
                .iter()
                .find(|service| service.service_type.to_lowercase().contains(&exact))
            {
                return Ok((**service).clone());
            }
            Err(DiscoveryError(format!(
                "{} services match \"{name}\"; be more specific",
                many.len()
            )))
        }
    }
}

fn child_text(node: roxmltree::Node<'_, '_>, name: &str) -> String {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Service, find_service_by_name};

    #[test]
    fn exact_local_name_wins_among_substring_matches() {
        let services = vec![
            Service {
                service_type: "urn:test:service:ThingExtra:1".to_owned(),
                control_url: "/extra".to_owned(),
            },
            Service {
                service_type: "urn:test:service:Thing:1".to_owned(),
                control_url: "/thing".to_owned(),
            },
        ];
        assert_eq!(
            find_service_by_name(&services, "Thing")
                .unwrap()
                .control_url,
            "/thing"
        );
    }
}
