use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use slatefs_core::volume::Volume;

type RegistryMap = HashMap<(String, String), Arc<Volume>>;

#[derive(Clone, Default)]
pub struct LiveVolumeRegistry {
    inner: Arc<RwLock<RegistryMap>>,
}

impl LiveVolumeRegistry {
    pub fn insert(&self, tenant: String, volume: String, value: Arc<Volume>) {
        self.inner
            .write()
            .expect("consumer registry poisoned")
            .insert((tenant, volume), value);
    }

    #[must_use]
    pub fn get(&self, tenant: &str, volume: &str) -> Option<Arc<Volume>> {
        self.inner
            .read()
            .expect("consumer registry poisoned")
            .get(&(tenant.to_owned(), volume.to_owned()))
            .cloned()
    }

    pub fn remove(&self, tenant: &str, volume: &str) -> Option<Arc<Volume>> {
        self.inner
            .write()
            .expect("consumer registry poisoned")
            .remove(&(tenant.to_owned(), volume.to_owned()))
    }

    pub fn retain(&self, mut keep: impl FnMut(&str, &str) -> bool) {
        self.inner
            .write()
            .expect("consumer registry poisoned")
            .retain(|(tenant, volume), _| keep(tenant, volume));
    }

    #[must_use]
    pub fn contains(&self, tenant: &str, volume: &str) -> bool {
        self.get(tenant, volume).is_some()
    }
}
