#![deny(unsafe_code)]

use std::io::{self, Write};

use serde::Serialize;
use serde_json::Value;

use crate::OutputFormat;

/// Serialize a command payload using the same JSON-first contract as the Go CLI.
pub fn render<T: Serialize>(value: &T, format: OutputFormat) -> Result<String, String> {
    match format {
        OutputFormat::Text => Err("text output requires a command renderer".to_owned()),
        OutputFormat::Json => serde_json::to_string_pretty(value)
            .map(|json| format!("{json}\n"))
            .map_err(|error| error.to_string()),
        OutputFormat::Yaml => {
            let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
            let mut output = String::new();
            render_yaml(&value, 0, &mut output);
            Ok(output)
        }
    }
}

/// Write a structured payload without allowing serialization failures to reach stdout.
pub fn write<T: Serialize, W: Write>(
    writer: &mut W,
    value: &T,
    format: OutputFormat,
) -> io::Result<()> {
    let rendered = render(value, format).map_err(io::Error::other)?;
    writer.write_all(rendered.as_bytes())
}

fn render_yaml(value: &Value, indent: usize, output: &mut String) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                write_indent(output, indent);
                if is_scalar(child) {
                    output.push_str(key);
                    output.push_str(": ");
                    output.push_str(&yaml_scalar(child));
                    output.push('\n');
                } else {
                    output.push_str(key);
                    output.push_str(":\n");
                    render_yaml(child, indent + 2, output);
                }
            }
        }
        Value::Array(values) => {
            if values.is_empty() {
                write_indent(output, indent);
                output.push_str("[]\n");
            } else {
                for child in values {
                    write_indent(output, indent);
                    if is_scalar(child) {
                        output.push_str("- ");
                        output.push_str(&yaml_scalar(child));
                        output.push('\n');
                    } else {
                        output.push_str("-\n");
                        render_yaml(child, indent + 2, output);
                    }
                }
            }
        }
        _ => {
            write_indent(output, indent);
            output.push_str(&yaml_scalar(value));
            output.push('\n');
        }
    }
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Object(_) | Value::Array(_))
}

fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) if is_plain_yaml_string(value) => value.clone(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned()),
        Value::Object(_) | Value::Array(_) => unreachable!(),
    }
}

fn is_plain_yaml_string(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            !character.is_control() && !matches!(character, ':' | '#' | '\n' | '\r')
        })
        && !value.starts_with([
            '-', '?', '!', '*', '&', '|', '>', '@', '`', '{', '}', '[', ']', ',', '%', '\"', '\'',
        ])
        && !matches!(
            value,
            "null" | "Null" | "NULL" | "~" | "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
        )
        && !is_yaml_number(value)
}

fn is_yaml_number(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let digits = match trimmed.as_bytes().first() {
        Some(b'+') | Some(b'-') => &trimmed[1..],
        _ => trimmed,
    };
    if digits.is_empty() {
        return false;
    }
    digits.parse::<i64>().is_ok()
        || digits.parse::<f64>().is_ok()
        || (digits.starts_with("0x") && u64::from_str_radix(&digits[2..], 16).is_ok())
}

fn write_indent(output: &mut String, indent: usize) {
    output.extend(std::iter::repeat_n(' ', indent));
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::OutputFormat;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Fixture {
        first: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        omitted: Option<String>,
        values: Vec<u32>,
    }

    #[test]
    fn json_uses_pretty_output_and_omits_optional_fields() {
        let value = Fixture {
            first: "ok".to_owned(),
            omitted: None,
            values: vec![1, 2],
        };
        assert_eq!(
            render(&value, OutputFormat::Json).unwrap(),
            "{\n  \"first\": \"ok\",\n  \"values\": [\n    1,\n    2\n  ]\n}\n"
        );
    }

    #[test]
    fn yaml_uses_the_same_omission_and_order_contract() {
        let value = Fixture {
            first: "ok".to_owned(),
            omitted: None,
            values: vec![1, 2],
        };
        assert_eq!(
            render(&value, OutputFormat::Yaml).unwrap(),
            "first: ok\nvalues:\n  - 1\n  - 2\n"
        );
    }
}
