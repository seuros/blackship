//! Versioned output contract for CLI consumers.

use crate::cli::OutputFormat;
use crate::error::{Error, Result};
use serde::Serialize;
use std::fmt;

/// Current JSON contract version.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct SuccessEnvelope<'a, T> {
    schema_version: u32,
    ok: bool,
    data: &'a T,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema_version: u32,
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    message: &'a str,
}

/// Error returned at the executable boundary, rendered for the requested format.
#[derive(Debug)]
pub struct CliError {
    format: OutputFormat,
    source: Error,
}

impl CliError {
    pub fn new(format: OutputFormat, source: Error) -> Self {
        Self { format, source }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.format == OutputFormat::Json {
            let message = self.source.to_string();
            let envelope = ErrorEnvelope {
                schema_version: SCHEMA_VERSION,
                ok: false,
                error: ErrorBody {
                    code: self.source.code(),
                    message: &message,
                },
            };
            let rendered = serde_json::to_string(&envelope).map_err(|_| fmt::Error)?;
            f.write_str(&rendered)
        } else {
            write!(f, "Error: {}", self.source)
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Print a successful JSON result using the public envelope.
pub fn print_success<T: Serialize>(data: &T) -> Result<()> {
    let envelope = SuccessEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: true,
        data,
    };
    let rendered = serde_json::to_string_pretty(&envelope)
        .map_err(|error| Error::JsonOutput(error.to_string()))?;
    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_envelope_is_versioned() {
        let envelope = SuccessEnvelope {
            schema_version: SCHEMA_VERSION,
            ok: true,
            data: &vec!["jail-a"],
        };
        let value = serde_json::to_value(envelope).unwrap();

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"][0], "jail-a");
    }

    #[test]
    fn errors_have_stable_codes() {
        let error = CliError::new(OutputFormat::Json, Error::JailNotFound("web".into()));
        let value: serde_json::Value = serde_json::from_str(&error.to_string()).unwrap();

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "jail_not_found");
        assert_eq!(value["error"]["message"], "Jail 'web' not found");
    }
}
