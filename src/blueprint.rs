//! Template system for building jails
//!
//! Provides:
//! - Jailfile parsing (TOML and line-based formats)
//! - Build instructions (FROM, RUN, COPY, EXPOSE, CMD, etc.)
//! - Build execution with context
//! - Template management

pub mod context;
pub mod executor;
pub mod instructions;
pub mod parser;

pub use context::BuildContext;
pub use executor::TemplateExecutor;
pub use instructions::Instruction;
pub use parser::parse_jailfile;
