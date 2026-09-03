use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::kms::SecretPayload;

pub struct SecretCache {
    inner: ArcSwap<HashMap<String, SecretPayload>>,
}

impl SecretCache {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    pub fn snapshot(&self) -> Arc<HashMap<String, SecretPayload>> {
        self.inner.load_full()
    }

    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<SecretPayload> {
        self.snapshot()
            .get(key)
            .filter(|entry| entry.is_valid())
            .cloned()
    }

    #[allow(dead_code)]
    pub fn values(&self) -> HashMap<String, SecretPayload> {
        self.snapshot().as_ref().clone()
    }

    pub fn update_all(&self, new_map: HashMap<String, SecretPayload>) {
        self.inner.store(Arc::new(new_map));
    }

    #[allow(dead_code)]
    pub fn update_single(&self, key: String, value: SecretPayload) {
        let mut snapshot = self.snapshot().as_ref().clone();
        snapshot.insert(key, value);
        self.inner.store(Arc::new(snapshot));
    }

    pub fn purge_expired(&self) {
        let snapshot = self.snapshot();
        let filtered: HashMap<String, SecretPayload> = snapshot
            .iter()
            .filter(|(_, value)| value.is_valid())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        self.update_all(filtered);
    }

    pub fn keys_expiring_within(&self, window: Duration) -> Vec<String> {
        let snapshot = self.snapshot();
        let threshold = std::time::Instant::now() + window;
        snapshot
            .iter()
            .filter_map(|(key, value)| {
                value
                    .expires_at
                    .and_then(|expires_at| (expires_at <= threshold).then(|| key.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::kms::SecretPayload;

    use super::SecretCache;

    #[test]
    fn update_all_replaces_snapshot_atomically() {
        let cache = SecretCache::new();
        let first = HashMap::from([(
            "alpha".to_string(),
            SecretPayload {
                key: "alpha".to_string(),
                value: zeroize::Zeroizing::new(b"one".to_vec()),
                expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(60)),
            },
        )]);
        cache.update_all(first.clone());
        assert_eq!(cache.get("alpha").unwrap().key, "alpha");

        let second = HashMap::from([(
            "beta".to_string(),
            SecretPayload {
                key: "beta".to_string(),
                value: zeroize::Zeroizing::new(b"two".to_vec()),
                expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(30)),
            },
        )]);
        cache.update_all(second.clone());
        assert!(cache.get("alpha").is_none());
        assert_eq!(cache.get("beta").unwrap().key, "beta");
    }

    #[test]
    fn update_single_adds_value_without_mutating_existing_snapshot() {
        let cache = SecretCache::new();
        let payload = SecretPayload {
            key: "primary".to_string(),
            value: zeroize::Zeroizing::new(b"primary-value".to_vec()),
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(100)),
        };
        cache.update_single("primary".to_string(), payload.clone());

        let rotated = SecretPayload {
            key: "primary".to_string(),
            value: zeroize::Zeroizing::new(b"rotated".to_vec()),
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(100)),
        };
        cache.update_single("primary".to_string(), rotated.clone());

        let stored = cache.get("primary").unwrap();
        assert_eq!(stored.value.as_slice(), rotated.value.as_slice());
    }
}
