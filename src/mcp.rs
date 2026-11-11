//! MCP server for authoring and validating jail configuration, over stdio or
//! Streamable HTTP. On stdio, stdout is the JSON-RPC stream: never print;
//! diagnostics go to `mcp.log` on both transports.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcp_host::prelude::*;
use mcp_host::registry::router::{McpResourceTemplateRouter, McpRouter};
use mcp_host::transport::http::{HttpBearerAuthConfig, HttpTransport, HttpTransportConfig};

use crate::error;
use crate::error::Result;

mod elicit;
mod prompts;
mod resources;
mod tools;

/// Shared state handed to tool, prompt, and resource handlers.
pub struct McpState {
    config_path: PathBuf,
}

impl McpState {
    /// Combine the auto-mounted tool, prompt, and resource routers.
    fn router() -> std::result::Result<McpRouter<Self>, AppsError> {
        Ok(McpRouter::new(
            tools::router(),
            prompts::router(),
            resources::router()?,
            McpResourceTemplateRouter::new(),
        ))
    }
}

const INSTRUCTIONS: &str = "Authors and validates blackship jail configuration \
     (blackship.toml manifests, Jailfiles) for this FreeBSD host. \
     `blackship:///host` is ground truth: FreeBSD version, CPU, memory and what \
     jails already claim, disk, networks and free addresses, releases. \
     Schemas: `blackship:///schema/{manifest,jailfile}`. \
     Writes require operator approval via elicitation; a declined write is final.";

/// Appended on stdio only: the client runs on the host and can run the CLI.
const LOCAL_INSTRUCTIONS: &str = " CLI: `blackship:///man`.";

/// The CLI manual, served on stdio only. A remote client cannot run the CLI.
const LOCAL_ONLY_RESOURCES: [&str; 2] = ["blackship:///man", "blackship:///man.kdl"];

/// Endpoint path for the HTTP transport.
const HTTP_ENDPOINT: &str = "/mcp";

/// Principal recorded for requests carrying the operator's token.
const HTTP_PRINCIPAL: &str = "operator";

/// Where the server talks to its client.
pub enum Transport {
    Stdio,
    Http {
        addr: std::net::SocketAddr,
        token: Option<String>,
    },
}

impl Transport {
    /// HTTP on `addr`. Off loopback a token is mandatory: the tools describe
    /// the host and write files on it.
    pub fn http(addr: &str, token: Option<String>) -> Result<Self> {
        let addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            error::Error::InvalidArgument(format!(
                "--listen expects an address and port such as 127.0.0.1:7340: {e}"
            ))
        })?;
        let token = token.filter(|t| !t.is_empty());
        if !addr.ip().is_loopback() && token.is_none() {
            return Err(error::Error::InvalidArgument(format!(
                "refusing to serve MCP on {addr} without authentication: set BLACKSHIP_MCP_TOKEN"
            )));
        }
        Ok(Self::Http { addr, token })
    }
}

/// Run the MCP server until the client closes stdio or the HTTP listener stops.
pub async fn serve(config_path: &Path, transport: Transport) -> Result<()> {
    init_logging();

    let state = Arc::new(McpState {
        config_path: config_path.to_path_buf(),
    });

    let local = matches!(transport, Transport::Stdio);
    let instructions = if local {
        format!("{INSTRUCTIONS}{LOCAL_INSTRUCTIONS}")
    } else {
        INSTRUCTIONS.to_string()
    };

    let server = Server::builder("blackship", env!("CARGO_PKG_VERSION"))
        .with_instructions(instructions)
        .with_tools(true)
        .with_prompts(true)
        .with_resources(true, false)
        .build();

    let router = McpState::router()
        .map_err(|e| error::Error::User(format!("MCP resource registration failed: {e}")))?;
    server
        .register_router(router, state)
        .map_err(|e| error::Error::User(format!("MCP route registration failed: {e}")))?;
    if !local {
        // Before any session exists, so no list_changed is sent.
        for uri in LOCAL_ONLY_RESOURCES {
            server.resource_manager().remove(uri);
        }
    }

    tracing::info!(
        tools = server.tool_registry().list().len(),
        resources = server.resource_manager().list().len(),
        "blackship MCP server starting"
    );

    match transport {
        Transport::Stdio => server
            .run(StdioTransport::new())
            .await
            .map_err(|e| error::Error::User(format!("MCP server failed: {e}"))),
        Transport::Http { addr, token } => serve_http(server, addr, token).await,
    }
}

async fn serve_http(
    server: Server,
    addr: std::net::SocketAddr,
    token: Option<String>,
) -> Result<()> {
    let bearer_auth = token
        .map(|token| HttpBearerAuthConfig::new(token, HTTP_PRINCIPAL))
        .transpose()
        .map_err(|e| error::Error::InvalidArgument(format!("BLACKSHIP_MCP_TOKEN: {e}")))?
        .map(Into::into);
    let authenticated = bearer_auth.is_some();
    let config = HttpTransportConfig {
        bind_addr: addr.to_string(),
        endpoint: HTTP_ENDPOINT.to_string(),
        // Loopback keeps mcp-host's Host/Origin checks against DNS rebinding.
        localhost_only: addr.ip().is_loopback(),
        bearer_auth,
        ..Default::default()
    };

    eprintln!(
        "blackship MCP listening on http://{addr}{HTTP_ENDPOINT}{}",
        if authenticated {
            " (bearer token required)"
        } else {
            ""
        }
    );
    tracing::info!(%addr, authenticated, "blackship MCP serving HTTP");

    HttpTransport::new(server, config)
        .run()
        .await
        .map_err(|e| error::Error::User(format!("MCP HTTP server failed: {e}")))
}

/// Install a file-backed tracing subscriber, or none if the log dir is unusable.
fn init_logging() {
    let dir = crate::manifest::get_xdg_data_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }

    let Ok(file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("mcp.log"))
    else {
        return;
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Fails only if a subscriber is already set.
    let _ = tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)
        .with_env_filter(filter)
        .try_init();
}

#[cfg(test)]
mod tests;
