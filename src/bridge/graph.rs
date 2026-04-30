//! Dependency graph operations

use crate::error::{Error, Result};
use petgraph::algo::toposort;

use super::Bridge;

impl Bridge {
    /// Get the start order (topological sort)
    pub fn start_order(&self) -> Result<Vec<&str>> {
        toposort(&self.graph, None)
            .map(|nodes| nodes.iter().map(|n| self.graph[*n].as_str()).collect())
            .map_err(|cycle| {
                let cycle_node = &self.graph[cycle.node_id()];
                Error::ConfigValidation(format!(
                    "Cyclic dependency detected involving jail '{}'",
                    cycle_node
                ))
            })
    }

    /// Get the stop order (reverse of start order)
    pub fn stop_order(&self) -> Result<Vec<&str>> {
        let mut order = self.start_order()?;
        order.reverse();
        Ok(order)
    }

    /// Get all dependencies of a jail (including the jail itself)
    pub(super) fn get_dependencies(&self, name: &str) -> Result<Vec<&str>> {
        let (service_name, _full_name) = self.resolve_jail_names(name)?;
        let order = self.start_order()?;
        let idx = order
            .iter()
            .position(|n| *n == service_name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        Ok(order[..=idx].to_vec())
    }

    /// Get all dependents of a jail (including the jail itself)
    pub(super) fn get_dependents(&self, name: &str) -> Result<Vec<&str>> {
        let (service_name, _full_name) = self.resolve_jail_names(name)?;
        let order = self.stop_order()?;
        let idx = order
            .iter()
            .position(|n| *n == service_name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        Ok(order[..=idx].to_vec())
    }
}
