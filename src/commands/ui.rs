//! Placeholder web UI command: read-only, loopback only

use crate::error::Result;
use crate::manifest::BlackshipConfig;

pub fn handle(config: Option<&BlackshipConfig>, listen: &str) -> Result<()> {
    let addr = crate::ui::listen_addr(listen)?;
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(crate::ui::serve(addr, config))
}
