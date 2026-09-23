//! Dependency graph operations

use crate::error::{Error, Result};
use crate::scope::CascadePolicy;
use petgraph::algo::toposort;
use petgraph::visit::{Bfs, Reversed};
use std::collections::HashSet;

use super::Bridge;

/// What a `down` must do, split by the targets' cascade policies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownPlan {
    /// Jails to stop, in stop order.
    pub stop: Vec<String>,
    /// Dependents left running but fenced off at the firewall, in stop order.
    pub isolate: Vec<String>,
}

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

    /// Nodes reachable from `roots` along dependency edges, roots included.
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
        Ok(self.down_plan(jail)?.stop)
    }

    /// The cascade policy declared for a service, `Strict` when unspecified.
    fn cascade_for(&self, service_name: &str) -> CascadePolicy {
        self.config
            .get_jail(service_name)
            .map(|jail| jail.cascade)
            .unwrap_or_default()
    }

    /// Resolve a `down` target into the jails to stop and the jails to fence.
    pub(super) fn down_plan(&self, jail: Option<&str>) -> Result<DownPlan> {
        let Some(name) = jail else {
            return Ok(DownPlan {
                stop: self.stop_order()?.into_iter().map(String::from).collect(),
                isolate: Vec::new(),
            });
        };

        let roots = self.expand_selector(name)?;
        let mut stop: HashSet<String> = roots.iter().cloned().collect();
        let mut isolate: HashSet<String> = HashSet::new();

        for root in &roots {
            let single = std::slice::from_ref(root);
            match self.cascade_for(root) {
                CascadePolicy::Strict => stop.extend(self.reachable(single, true)),
                CascadePolicy::Detach => {}
                CascadePolicy::Isolate => isolate.extend(
                    self.reachable(single, true)
                        .into_iter()
                        .filter(|n| n != root),
                ),
            }
        }

        isolate.retain(|name| !stop.contains(name));

        let order = self.stop_order()?;
        let in_stop_order = |set: &HashSet<String>| -> Vec<String> {
            order
                .iter()
                .filter(|n| set.contains(**n))
                .map(|n| n.to_string())
                .collect()
        };

        Ok(DownPlan {
            stop: in_stop_order(&stop),
            isolate: in_stop_order(&isolate),
        })
    }
}
