use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use secrecy::SecretString;

struct CacheEntry {
    value: SecretString,
    expires_at: Instant,
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
    pub fn get(&self, key: &str) -> Option<SecretString> {
        let guard = self.inner.read().expect("cache lock poisoned");
        guard.get(key).and_then(|entry| {
            if entry.expires_at > Instant::now() {
                Some(entry.value.clone())
            } else {
                None
            }
        })
    }

    pub fn insert(&self, key: String, value: SecretString, ttl: Duration) {
        let mut guard = self.inner.write().expect("cache lock poisoned");
        guard.insert(
            key,
            CacheEntry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    #[allow(dead_code)]
    pub fn retain_keys(&self, valid_keys: &[String]) {
        let mut guard = self.inner.write().expect("cache lock poisoned");
        guard.retain(|k, _| valid_keys.contains(k));
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
