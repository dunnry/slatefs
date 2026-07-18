use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Default)]
pub struct ConsumerMetrics {
    inner: Arc<Mutex<BTreeMap<(String, u16), OperationMetrics>>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationMetrics {
    pub requests: u64,
    pub errors: u64,
    pub response_bytes: u64,
    pub duration_nanos: u64,
}

impl ConsumerMetrics {
    pub fn record(&self, operation: &str, status: u16, bytes: u64, duration: Duration) {
        let mut values = self.inner.lock().expect("consumer metrics poisoned");
        let value = values.entry((operation.to_owned(), status)).or_default();
        value.requests = value.requests.saturating_add(1);
        value.errors = value.errors.saturating_add(u64::from(status >= 400));
        value.response_bytes = value.response_bytes.saturating_add(bytes);
        value.duration_nanos = value
            .duration_nanos
            .saturating_add(duration.as_nanos() as u64);
    }

    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<(String, u16), OperationMetrics> {
        self.inner
            .lock()
            .expect("consumer metrics poisoned")
            .clone()
    }
}
