use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub struct CacheEntry {
    #[allow(dead_code)]
    pub value: Zeroizing<Vec<u8>>,
    pub expires_at: Instant,
}

pub struct SecretCache {
    inner: RwLock<HashMap<String, CacheEntry>>,
}

impl SecretCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        let guard = self.inner.read().expect("cache lock poisoned");
        guard.get(key).and_then(|entry| {
            if entry.expires_at > Instant::now() {
                Some(entry.value.clone())
            } else {
                None
            }
        })
    }

    pub fn insert(&self, key: String, value: Zeroizing<Vec<u8>>, ttl: Duration) {
        let mut guard = self.inner.write().expect("cache lock poisoned");
        guard.insert(
            key,
            CacheEntry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn purge_expired(&self) {
        let mut guard = self.inner.write().expect("cache lock poisoned");
        let now = Instant::now();
        guard.retain(|_, entry| entry.expires_at > now);
    }

    pub fn keys_expiring_within(&self, window: Duration) -> Vec<String> {
        let guard = self.inner.read().expect("cache lock poisoned");
        let threshold = Instant::now() + window;
        guard
            .iter()
            .filter(|(_, entry)| entry.expires_at <= threshold)
            .map(|(key, _)| key.clone())
            .collect()
    }
}
