#![deny(unsafe_code)]

//! Language-neutral CLI contract helpers used during the Rust port.

/// Public tool name preserved from the Go binary.
pub const TOOL: &str = "symfritz";

/// Supported structured-output modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
}

/// Resolve the global output flags using the Go implementation's semantics.
pub fn resolve_output_format(value: &str, json: bool) -> Result<OutputFormat, String> {
    let normalized = value.trim().to_ascii_lowercase();
    let format = match normalized.as_str() {
        "" | "text" => OutputFormat::Text,
        "json" => OutputFormat::Json,
        "yaml" => OutputFormat::Yaml,
        other => {
            return Err(format!(
                "invalid output format: unsupported output format \"{other}\" (want text, json, or yaml)"
            ));
        }
    };

    if json && format == OutputFormat::Yaml {
        return Err(
            "conflicting output formats: conflicting output formats \"yaml\" and \"json\""
                .to_owned(),
        );
    }

    if json {
        Ok(OutputFormat::Json)
    } else {
        Ok(format)
    }
}

/// Render the version command exactly as the Go oracle does.
///
/// ```
/// use symfritz_cli::{OutputFormat, render_version};
///
/// assert_eq!(render_version(OutputFormat::Text, "dev"), "symfritz dev\n");
/// ```
pub fn render_version(format: OutputFormat, version: &str) -> String {
    match format {
        OutputFormat::Text => format!("{TOOL} {version}\n"),
        OutputFormat::Json => {
            format!("{{\"tool\":\"{TOOL}\",\"version\":\"{version}\",\"schema_version\":1}}\n")
        }
        OutputFormat::Yaml => {
            format!("schema_version: 1\ntool: {TOOL}\nversion: {version}\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, resolve_output_format};

    #[test]
    fn output_format_is_case_insensitive() {
        assert_eq!(
            resolve_output_format(" JSON ", false),
            Ok(OutputFormat::Json)
        );
    }

    #[test]
    fn json_flag_conflicts_with_yaml() {
        assert_eq!(
            resolve_output_format("yaml", true),
            Err(
                "conflicting output formats: conflicting output formats \"yaml\" and \"json\""
                    .to_owned()
            )
        );
    }

    #[test]
    fn unsupported_output_matches_go_error() {
        assert_eq!(
            resolve_output_format("wat", false),
            Err(
                "invalid output format: unsupported output format \"wat\" (want text, json, or yaml)"
                    .to_owned()
            )
        );
    }
}
