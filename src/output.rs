//! Versioned output contract for CLI consumers.

use crate::cli::OutputFormat;
use crate::error::{Error, Result};
use serde::Serialize;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};

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
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    output: &'a [String],
}

/// Error returned at the executable boundary, rendered for the requested format.
#[derive(Debug)]
pub struct CliError {
    format: OutputFormat,
    source: Error,
}

impl CliError {
    #[must_use]
    pub const fn new(format: OutputFormat, source: Error) -> Self {
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
                    output: self.source.output(),
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

/// Run an operation with stdout captured, then restore stdout before returning.
///
/// Mutating commands often stream human progress from lower layers. JSON
/// callers still need exactly one document on stdout, so the progress is
/// returned as message lines inside the structured result instead.
pub fn capture_stdout<T>(operation: impl FnOnce() -> Result<T>) -> Result<(T, Vec<String>)> {
    capture_fd(&Stdout, operation)
}

/// The descriptor a capture redirects.
trait Captured {
    /// Flush whatever is buffered in front of the descriptor.
    fn flush(&self) -> std::io::Result<()>;
    /// A duplicate of where the descriptor points now.
    fn save(&self) -> std::io::Result<OwnedFd>;
    /// Make the descriptor point at `to`.
    fn point_at(&self, to: &impl AsFd) -> std::io::Result<()>;
}

/// fd 1.
struct Stdout;

impl Captured for Stdout {
    fn flush(&self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }

    fn save(&self) -> std::io::Result<OwnedFd> {
        nix::unistd::dup(std::io::stdout()).map_err(std::io::Error::from)
    }

    fn point_at(&self, to: &impl AsFd) -> std::io::Result<()> {
        nix::unistd::dup2_stdout(to).map_err(std::io::Error::from)
    }
}

fn capture_fd<T>(
    target: &impl Captured,
    operation: impl FnOnce() -> Result<T>,
) -> Result<(T, Vec<String>)> {
    struct Restore<'a, C: Captured>(&'a C, OwnedFd);

    impl<C: Captured> Drop for Restore<'_, C> {
        fn drop(&mut self) {
            let _ = self.0.point_at(&self.1);
        }
    }

    target.flush()?;
    let restore = Restore(target, target.save()?);
    let mut captured = tempfile::tempfile()?;
    target.point_at(&captured)?;

    let result = operation();
    target.flush()?;
    drop(restore);

    captured.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    captured.read_to_end(&mut bytes)?;
    let messages: Vec<String> = String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::to_owned)
        .collect();
    match result {
        Ok(value) => Ok((value, messages)),
        Err(source) if messages.is_empty() => Err(source),
        Err(source) => Err(Error::WithOutput {
            source: Box::new(source),
            output: messages,
        }),
    }
}

#[cfg(test)]
mod tests;
