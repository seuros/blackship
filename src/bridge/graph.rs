//! Dependency graph operations

use crate::error::{Error, Result};
use petgraph::algo::toposort;
use petgraph::visit::{Bfs, Reversed};
use std::collections::HashSet;

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

    /// Nodes reachable from `roots` along dependency edges.
    ///
    /// Edges point dep -> dependent, so following them yields dependents and
    /// following them reversed yields dependencies. Roots are included.
    fn reachable(&self, roots: &[String], dependents: bool) -> HashSet<String> {
        let mut set = HashSet::new();
        for root in roots {
            let Some(start) = self.graph.node_indices().find(|&n| self.graph[n] == *root) else {
                continue;
            };
            if dependents {
                let mut bfs = Bfs::new(&self.graph, start);
                while let Some(node) = bfs.next(&self.graph) {
                    set.insert(self.graph[node].clone());
                }
            } else {
                let reversed = Reversed(&self.graph);
                let mut bfs = Bfs::new(&reversed, start);
                while let Some(node) = bfs.next(&reversed) {
                    set.insert(self.graph[node].clone());
                }
            }
        }
        set
    }

    /// Expand a target selector into service names: ALL, a tag carried by
    /// one or more jails, an exact service/full name, or a unique prefix.
    fn expand_selector(&self, selector: &str) -> Result<Vec<String>> {
        if selector.eq_ignore_ascii_case("all") {
            return Ok(self.config.jails.iter().map(|j| j.name.clone()).collect());
        }

        let tagged: Vec<String> = self
            .config
            .jails
            .iter()
            .filter(|j| j.tags.iter().any(|t| t == selector))
            .map(|j| j.name.clone())
            .collect();
        if !tagged.is_empty() {
            return Ok(tagged);
        }

        let (service_name, _) = self.resolve_jail_names(selector)?;
        Ok(vec![service_name])
    }

    /// Get all dependencies of a jail (including the jail itself)
    pub(super) fn get_dependencies(&self, name: &str) -> Result<Vec<&str>> {
        let roots = self.expand_selector(name)?;
        let set = self.reachable(&roots, false);
        Ok(self
            .start_order()?
            .into_iter()
            .filter(|n| set.contains(*n))
            .collect())
    }

    /// Get all dependents of a jail (including the jail itself)
    pub(super) fn get_dependents(&self, name: &str) -> Result<Vec<&str>> {
        let roots = self.expand_selector(name)?;
        let set = self.reachable(&roots, true);
        Ok(self
            .stop_order()?
            .into_iter()
            .filter(|n| set.contains(*n))
            .collect())
    }

    /// Ordered list of jails to bring up (selector + its deps, or all in start order)
    pub(super) fn jails_for_up(&self, jail: Option<&str>) -> Result<Vec<String>> {
        if let Some(name) = jail {
            Ok(self
                .get_dependencies(name)?
                .into_iter()
                .map(String::from)
                .collect())
        } else {
            Ok(self.start_order()?.into_iter().map(String::from).collect())
        }
    }

    /// Ordered list of jails to bring down (selector + its dependents, or all in stop order)
    pub(super) fn jails_for_down(&self, jail: Option<&str>) -> Result<Vec<String>> {
        if let Some(name) = jail {
            Ok(self
                .get_dependents(name)?
                .into_iter()
                .map(String::from)
                .collect())
        } else {
            Ok(self.stop_order()?.into_iter().map(String::from).collect())
        }
    }
}
