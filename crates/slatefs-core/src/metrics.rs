//! In-process metrics aggregation (plan §13, wired at Phase 3 for cache
//! hit-rate visibility). Implements SlateDB's `MetricsRecorder` so engine
//! metrics (block-cache and object-store-cache hits/misses, flush latency…)
//! land in a snapshotable map; the daemon logs the cache-relevant slice
//! periodically and exposes them through the daemon's Prometheus endpoint.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use slatedb_common::metrics::{CounterFn, GaugeFn, HistogramFn, MetricsRecorder, UpDownCounterFn};

#[derive(Debug, Clone, PartialEq)]
pub struct PrometheusSample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

impl PrometheusSample {
    pub fn new<I, K, V>(name: impl Into<String>, labels: I, value: f64) -> PrometheusSample
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        PrometheusSample {
            name: name.into(),
            labels: labels
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            value,
        }
    }
}

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

    pub fn prometheus_samples(&self, base_labels: &[(&str, &str)]) -> Vec<PrometheusSample> {
        self.snapshot()
            .into_iter()
            .map(|(key, value)| {
                let (name, labels) = split_flat_key(&key);
                let labels = base_labels
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                    .chain(labels)
                    .collect();
                PrometheusSample {
                    name: format!("slatefs_{name}"),
                    labels,
                    value,
                }
            })
            .collect()
    }
}

pub fn render_prometheus(samples: &[PrometheusSample]) -> String {
    let mut out = String::new();
    for sample in samples {
        out.push_str(&sanitize_metric_name(&sample.name));
        if !sample.labels.is_empty() {
            out.push('{');
            for (i, (name, value)) in sample.labels.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&sanitize_label_name(name));
                out.push_str("=\"");
                out.push_str(&escape_label_value(value));
                out.push('"');
            }
            out.push('}');
        }
        out.push(' ');
        out.push_str(&format_prometheus_value(sample.value));
        out.push('\n');
    }
    out
}

fn split_flat_key(key: &str) -> (String, Vec<(String, String)>) {
    let Some((name, labels)) = key.split_once('{') else {
        return (key.to_string(), Vec::new());
    };
    let Some(labels) = labels.strip_suffix('}') else {
        return (key.to_string(), Vec::new());
    };
    let labels = labels
        .split(',')
        .filter_map(|label| {
            let (name, value) = label.split_once('=')?;
            Some((name.to_string(), value.to_string()))
        })
        .collect();
    (name.to_string(), labels)
}

fn sanitize_metric_name(name: &str) -> String {
    sanitize_ident(name, true)
}

fn sanitize_label_name(name: &str) -> String {
    sanitize_ident(name, false)
}

fn sanitize_ident(name: &str, allow_colon: bool) -> String {
    let mut out = String::with_capacity(name.len().max(1));
    for (i, ch) in name.chars().enumerate() {
        let valid = ch == '_'
            || (allow_colon && ch == ':')
            || ch.is_ascii_alphabetic()
            || (i > 0 && ch.is_ascii_digit());
        out.push(if valid { ch } else { '_' });
    }
    if out.is_empty()
        || out
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit() || (!allow_colon && ch == ':'))
    {
        out.insert(0, '_');
    }
    out
}

fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

fn format_prometheus_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value == f64::INFINITY {
        "+Inf".to_string()
    } else if value == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else {
        value.to_string()
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

    #[test]
    fn renders_prometheus_text() {
        let r = AggregatingRecorder::default();
        let c = r.register_counter("cache.hits", "", &[("cache", "ram")]);
        c.increment(5);
        let h = r.register_histogram("flush.latency", "", &[], &[]);
        h.record(1.5);

        let mut samples = vec![PrometheusSample::new(
            "slatefs_volume.dead",
            [("tenant", "t\"1"), ("volume", "v\n1")],
            0.0,
        )];
        samples.extend(r.prometheus_samples(&[("tenant", "t1"), ("volume", "v1")]));
        let body = render_prometheus(&samples);

        assert!(body.contains("slatefs_volume_dead{tenant=\"t\\\"1\",volume=\"v\\n1\"} 0\n"));
        assert!(body.contains("slatefs_cache_hits{tenant=\"t1\",volume=\"v1\",cache=\"ram\"} 5\n"));
        assert!(body.contains("slatefs_flush_latency_count{tenant=\"t1\",volume=\"v1\"} 1\n"));
        assert!(body.contains("slatefs_flush_latency_sum{tenant=\"t1\",volume=\"v1\"} 1.5\n"));
    }
}
