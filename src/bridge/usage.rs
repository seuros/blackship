//! Racct usage sampling. Peaks are bounded by the sample interval.

use crate::scope::PeakMetrics;

use super::Bridge;

impl Bridge {
    /// Sample racct usage into the scope record's peaks and the OTel gauges.
    pub fn sample_usage(&self, full_name: &str) {
        let Ok(Some(mut scope)) = self.scope_store.get(full_name) else {
            return;
        };
        if scope.rctl_subject.is_none() {
            return;
        }

        let Ok(sample) = crate::rctl::get_usage(full_name) else {
            return;
        };
        if sample.is_empty() {
            return;
        }

        crate::telemetry::record_usage(full_name, &sample);

        scope.peak.observe(&sample);
        self.persist_scope(&mut scope);
    }

    /// The peaks recorded for a jail so far, if it has a scope record.
    pub fn peak_metrics(&self, full_name: &str) -> Option<PeakMetrics> {
        self.scope_store
            .get(full_name)
            .ok()
            .flatten()
            .map(|scope| scope.peak)
    }

    /// Peaks flattened for an audit record.
    pub(super) fn peak_details(&self, full_name: &str) -> Vec<(String, String)> {
        let Some(peak) = self.peak_metrics(full_name) else {
            return Vec::new();
        };
        if peak.resources.is_empty() {
            return Vec::new();
        }

        let mut details: Vec<(String, String)> = peak
            .resources
            .iter()
            .map(|(resource, value)| (format!("peak.{}", resource), value.to_string()))
            .collect();
        if let Some(samples) = peak.samples {
            details.push(("peak.samples".to_string(), samples.to_string()));
        }
        details
    }
}
