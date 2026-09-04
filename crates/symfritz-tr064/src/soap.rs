use std::collections::BTreeMap;

use quick_xml::{
    escape::resolve_predefined_entity,
    events::{BytesRef, Event},
    reader::Reader,
};

/// XML parsing failure at the SOAP boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoapParseError(pub String);

impl std::fmt::Display for SoapParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "tr064: parsing response: {}", self.0)
    }
}

impl std::error::Error for SoapParseError {}

/// Build the exact SOAP request bytes emitted by the Go implementation.
pub fn build_request(
    service_type: &str,
    action: &str,
    arguments: &BTreeMap<String, String>,
) -> Vec<u8> {
    let mut body = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
    body.push_str("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">");
    body.push_str("<s:Body>");
    body.push_str("<u:");
    body.push_str(action);
    body.push_str(" xmlns:u=\"");
    body.push_str(service_type);
    body.push_str("\">");
    for (key, value) in arguments {
        body.push('<');
        body.push_str(key);
        body.push('>');
        body.push_str(&escape_text(value));
        body.push_str("</");
        body.push_str(key);
        body.push('>');
    }
    body.push_str("</u:");
    body.push_str(action);
    body.push_str("></s:Body></s:Envelope>");
    body.into_bytes()
}

/// Parse direct output arguments from an action response, ignoring namespaces.
pub fn parse_response(
    xml: &[u8],
    action: &str,
) -> Result<BTreeMap<String, String>, SoapParseError> {
    let response_name = format!("{action}Response");
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut output: BTreeMap<String, String> = BTreeMap::new();
    let mut in_response = false;
    let mut current_key = String::new();
    let mut depth = 0_usize;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                depth += 1;
                let element_name = element.name();
                let name = local_name(element_name.as_ref());
                if name == response_name {
                    in_response = true;
                } else if in_response {
                    current_key = name.to_owned();
                }
            }
            Ok(Event::Text(text)) if in_response && !current_key.is_empty() => {
                output
                    .entry(current_key.clone())
                    .or_default()
                    .push_str(text.as_ref());
            }
            Ok(Event::CData(text)) if in_response && !current_key.is_empty() => {
                output
                    .entry(current_key.clone())
                    .or_default()
                    .push_str(text.as_ref());
            }
            Ok(Event::GeneralRef(reference)) if in_response && !current_key.is_empty() => {
                append_reference(output.entry(current_key.clone()).or_default(), &reference)?;
            }
            Ok(Event::End(element)) => {
                depth = depth.saturating_sub(1);
                if local_name(element.name().as_ref()) == response_name {
                    in_response = false;
                } else if in_response {
                    current_key.clear();
                }
            }
            Ok(Event::Eof) if depth == 0 => break,
            Ok(Event::Eof) => return Err(SoapParseError("unexpected EOF".to_owned())),
            Ok(_) => {}
            Err(error) => return Err(SoapParseError(error.to_string())),
        }
    }
    Ok(output)
}

/// Parse the numeric UPnP fault code and description from a SOAP fault body.
pub fn parse_fault(xml: &[u8]) -> (i32, String) {
    #[derive(Clone, Copy)]
    enum Field {
        Code,
        Description,
    }

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut field = None;
    let mut code = String::new();
    let mut description = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => match local_name(element.name().as_ref()) {
                "errorCode" => field = Some(Field::Code),
                "errorDescription" => field = Some(Field::Description),
                _ => {}
            },
            Ok(Event::Text(text)) => match field {
                Some(Field::Code) => code.push_str(text.as_ref()),
                Some(Field::Description) => description.push_str(text.as_ref()),
                None => {}
            },
            Ok(Event::CData(text)) => match field {
                Some(Field::Code) => code.push_str(text.as_ref()),
                Some(Field::Description) => description.push_str(text.as_ref()),
                None => {}
            },
            Ok(Event::GeneralRef(reference)) => {
                let target = match field {
                    Some(Field::Code) => &mut code,
                    Some(Field::Description) => &mut description,
                    None => continue,
                };
                if append_reference(target, &reference).is_err() {
                    break;
                }
            }
            Ok(Event::End(element)) => match local_name(element.name().as_ref()) {
                "errorCode" | "errorDescription" => field = None,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let code = code.trim().parse::<i32>().unwrap_or(0);
    let description = description.trim();
    if description.is_empty() {
        (code, raw_fallback(xml))
    } else {
        (code, description.to_owned())
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn append_reference(target: &mut String, reference: &BytesRef<'_>) -> Result<(), SoapParseError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|error| SoapParseError(error.to_string()))?
    {
        target.push(character);
        return Ok(());
    }
    if let Some(value) = resolve_predefined_entity(reference.as_ref()) {
        target.push_str(value);
        return Ok(());
    }
    Err(SoapParseError(format!(
        "unknown entity reference &{};",
        reference.as_ref()
    )))
}

fn escape_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '\'' => escaped.push_str("&#39;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&#34;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn raw_fallback(xml: &[u8]) -> String {
    let truncated = if xml.len() > 200 { &xml[..200] } else { xml };
    String::from_utf8_lossy(truncated).into_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{build_request, parse_fault};

    #[test]
    fn arguments_are_sorted_by_btree_map() {
        let arguments = BTreeMap::from([
            ("Zulu".to_owned(), "2".to_owned()),
            ("Alpha".to_owned(), "1".to_owned()),
        ]);
        let request = String::from_utf8(build_request("urn:test", "Run", &arguments)).unwrap();
        assert!(request.find("<Alpha>").unwrap() < request.find("<Zulu>").unwrap());
    }

    #[test]
    fn malformed_fault_falls_back_to_raw_body() {
        assert_eq!(parse_fault(b"<fault>"), (0, "<fault>".to_owned()));
    }
}
