//! In-process metrics aggregation (plan §13, wired at Phase 3 for cache
//! hit-rate visibility). Implements SlateDB's `MetricsRecorder` so engine
//! metrics (block-cache and object-store-cache hits/misses, flush latency…)
//! land in a snapshotable map; the daemon logs the cache-relevant slice
//! periodically. A Prometheus endpoint arrives with the Phase 6 dashboards.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use slatedb_common::metrics::{CounterFn, GaugeFn, HistogramFn, MetricsRecorder, UpDownCounterFn};

#[derive(Default)]
struct Value {
    /// Counter/gauge value, or histogram count; f64 bits for gauges.
    primary: AtomicU64,
    /// Histogram sum (f64 bits).
    sum: AtomicU64,
}

/// Aggregates every registered metric under `name{k=v,…}`.
#[derive(Default)]
pub struct AggregatingRecorder {
    values: Mutex<HashMap<String, Arc<Value>>>,
}

impl AggregatingRecorder {
    fn slot(&self, name: &str, labels: &[(&str, &str)]) -> Arc<Value> {
        let mut key = name.to_string();
        if !labels.is_empty() {
            key.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    key.push(',');
                }
                key.push_str(k);
                key.push('=');
                key.push_str(v);
            }
            key.push('}');
        }
        Arc::clone(
            self.values
                .lock()
                .expect("metrics poisoned")
                .entry(key)
                .or_default(),
        )
    }

    /// `(metric, value)` pairs; histograms appear as `name.count` and
    /// `name.sum`.
    pub fn snapshot(&self) -> Vec<(String, f64)> {
        let values = self.values.lock().expect("metrics poisoned");
        let mut out = Vec::with_capacity(values.len());
        for (key, v) in values.iter() {
            let primary = v.primary.load(Ordering::Relaxed);
            let sum = f64::from_bits(v.sum.load(Ordering::Relaxed));
            if sum != 0.0 {
                out.push((format!("{key}.count"), primary as f64));
                out.push((format!("{key}.sum"), sum));
            } else if key.contains("gauge") {
                out.push((key.clone(), f64::from_bits(primary)));
            } else {
                out.push((key.clone(), primary as f64));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

struct CounterHandle(Arc<Value>);
impl CounterFn for CounterHandle {
    fn increment(&self, value: u64) {
        self.0.primary.fetch_add(value, Ordering::Relaxed);
    }
}

struct GaugeHandle(Arc<Value>);
impl GaugeFn for GaugeHandle {
    fn set(&self, value: i64) {
        self.0
            .primary
            .store((value as f64).to_bits(), Ordering::Relaxed);
    }
}

struct UpDownHandle(Arc<Value>);
impl UpDownCounterFn for UpDownHandle {
    fn increment(&self, value: i64) {
        if value >= 0 {
            self.0.primary.fetch_add(value as u64, Ordering::Relaxed);
        } else {
            self.0
                .primary
                .fetch_sub(value.unsigned_abs(), Ordering::Relaxed);
        }
    }
}

struct HistogramHandle(Arc<Value>);
impl HistogramFn for HistogramHandle {
    fn record(&self, value: f64) {
        self.0.primary.fetch_add(1, Ordering::Relaxed);
        // f64 add via CAS loop on the bit representation.
        let mut current = self.0.sum.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(current) + value).to_bits();
            match self.0.sum.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}

impl MetricsRecorder for AggregatingRecorder {
    fn register_counter(
        &self,
        name: &str,
        _description: &str,
        labels: &[(&str, &str)],
    ) -> Arc<dyn CounterFn> {
        Arc::new(CounterHandle(self.slot(name, labels)))
    }

    fn register_gauge(
        &self,
        name: &str,
        _description: &str,
        labels: &[(&str, &str)],
    ) -> Arc<dyn GaugeFn> {
        Arc::new(GaugeHandle(self.slot(&format!("{name}.gauge"), labels)))
    }

    fn register_up_down_counter(
        &self,
        name: &str,
        _description: &str,
        labels: &[(&str, &str)],
    ) -> Arc<dyn UpDownCounterFn> {
        Arc::new(UpDownHandle(self.slot(name, labels)))
    }

    fn register_histogram(
        &self,
        name: &str,
        _description: &str,
        labels: &[(&str, &str)],
        _boundaries: &[f64],
    ) -> Arc<dyn HistogramFn> {
        Arc::new(HistogramHandle(self.slot(name, labels)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_and_snapshots() {
        let r = AggregatingRecorder::default();
        let c = r.register_counter("cache.hits", "", &[("volume", "v1")]);
        c.increment(3);
        c.increment(2);
        let h = r.register_histogram("flush.latency", "", &[], &[]);
        h.record(0.5);
        h.record(1.5);
        let snap: HashMap<_, _> = r.snapshot().into_iter().collect();
        assert_eq!(snap["cache.hits{volume=v1}"], 5.0);
        assert_eq!(snap["flush.latency.count"], 2.0);
        assert_eq!(snap["flush.latency.sum"], 2.0);
    }
}
