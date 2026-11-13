//! Placeholder web UI: one page and one Datastar SSE stream. Read-only and
//! unauthenticated, so it only binds to loopback.

use std::sync::Arc;
use std::time::Duration;

use rama::error::BoxError;
use rama::futures::GracefulStream;
use rama::futures::async_stream::stream_fn;
use rama::futures::future::{Either, select};
use rama::graceful::{Shutdown, WeakShutdownGuard};
use rama::http::layer::error_handling::ErrorHandlerLayer;
use rama::http::protocols::html::{IntoHtml as _, body, h1, head, html, meta, p, script, title};
use rama::http::server::HttpServer;
use rama::http::service::web::Router;
use rama::http::service::web::extract::State;
use rama::http::service::web::response::{DatastarScript, IntoResponse, Sse};
use rama::http::sse::datastar::{DatastarEvent, PatchElements};
use rama::http::sse::server::KeepAlive;
use rama::net::address::SocketAddress;
use rama::rt::Executor;
use rama::utils::str::NonEmptyStr;
use rama::Layer as _;

use crate::error::{Error, Result};
use crate::jail::jail_getid;
use crate::manifest::BlackshipConfig;

const REFRESH: Duration = Duration::from_secs(2);
const GRACE: Duration = Duration::from_secs(2);

/// Jails named in the manifest, plus the shutdown signal streams end on.
struct Ui {
    names: Vec<String>,
    shutdown: WeakShutdownGuard,
}

impl Ui {
    fn new(config: Option<&BlackshipConfig>, shutdown: WeakShutdownGuard) -> Self {
        let names = config.map_or_else(Vec::new, |config| {
            config
                .jails
                .iter()
                .map(|jail| config.jail_name(&jail.name))
                .collect()
        });
        Self { names, shutdown }
    }

    fn running(&self) -> usize {
        self.names
            .iter()
            .filter(|name| jail_getid(name).is_ok())
            .count()
    }
}

/// Parse `--listen`, refusing anything that is not loopback.
pub fn listen_addr(addr: &str) -> Result<SocketAddress> {
    let addr: SocketAddress = addr.parse().map_err(|e| {
        Error::InvalidArgument(format!(
            "--listen expects an address and port such as 127.0.0.1:7341: {e}"
        ))
    })?;
    if !addr.ip_addr.is_loopback() {
        return Err(Error::InvalidArgument(format!(
            "refusing to serve the unauthenticated UI on {addr}: use a loopback address"
        )));
    }
    Ok(addr)
}

fn fleet_fragment(version: &str, running: usize, total: usize) -> String {
    p!(
        id = "fleet",
        "blackship ",
        version,
        ": ",
        running,
        " of ",
        total,
        " jails running"
    )
    .into_string()
}

fn patch(html: String) -> std::result::Result<DatastarEvent, BoxError> {
    let elements = NonEmptyStr::try_from(html)?;
    Ok(PatchElements::new(elements).try_into_datastar_event()?)
}

async fn page() -> impl IntoResponse {
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            title!("blackship"),
            script!(r#type = "module", src = "/datastar.js"),
        ),
        body!(
            "data-init" = "@get('/stream')",
            h1!("blackship"),
            p!("Placeholder. The real UI is not here yet."),
            p!(id = "fleet", "connecting..."),
        ),
    )
}

async fn datastar() -> impl IntoResponse {
    DatastarScript::new()
}

async fn stream(State(ui): State<Arc<Ui>>) -> impl IntoResponse {
    let events = stream_fn({
        let ui = ui.clone();
        move |mut yielder| async move {
            loop {
                let html =
                    fleet_fragment(env!("CARGO_PKG_VERSION"), ui.running(), ui.names.len());
                yielder.yield_item(patch(html)).await;
                tokio::time::sleep(REFRESH).await;
            }
        }
    });
    Sse::new(GracefulStream::new(ui.shutdown.clone().into_cancelled(), events))
        .with_keep_alive(KeepAlive::new())
}

/// Serve until interrupted.
pub async fn serve(addr: SocketAddress, config: Option<&BlackshipConfig>) -> Result<()> {
    let shutdown = Shutdown::default();
    let ui = Arc::new(Ui::new(config, shutdown.guard_weak()));
    let router = Router::new_with_state(ui)
        .with_get("/", page)
        .with_get("/datastar.js", datastar)
        .with_get("/stream", stream);

    eprintln!("blackship ui (unauthenticated placeholder) on http://{addr}/");
    let serving = shutdown.spawn_task_fn(async move |guard| {
        HttpServer::auto(Executor::graceful(guard))
            .listen(addr, Arc::new(ErrorHandlerLayer::new().into_layer(router)))
            .await
    });
    let stopped = shutdown.shutdown_with_limit(GRACE);

    match select(Box::pin(serving), Box::pin(stopped)).await {
        Either::Left((served, _)) => served
            .map_err(|e| Error::User(format!("UI server task failed: {e}")))?
            .map_err(|e| Error::User(format!("UI server failed: {e}"))),
        Either::Right(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests;
