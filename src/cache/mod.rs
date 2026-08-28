use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Pojedynczy wpis w cache — wartość sekretu wraz z momentem wygaśnięcia.
/// `SecretString` zapewnia zerowanie pamięci przy usunięciu (Drop).
struct CacheEntry {
    value: SecretString,
    expires_at: Instant,
}

/// Thread-safe cache sekretów w pamięci RAM.
///
/// Sekrety nigdy nie trafiają na dysk. Struktury wewnętrzne opierają się
/// o `secrecy::SecretString`, które implementuje zero-on-drop, dzięki
/// czemu usunięcie wpisu nadpisuje bufor pamięci przed zwolnieniem.
pub struct SecretCache {
    inner: RwLock<HashMap<String, CacheEntry>>,
}

impl SecretCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Zwraca kopię wartości sekretu, jeśli istnieje i nie wygasł.
    pub fn get(&self, key: &str) -> Option<SecretString> {
        let guard = self.inner.read().expect("cache lock poisoned");
        guard.get(key).and_then(|entry| {
            if entry.expires_at > Instant::now() {
                Some(SecretString::from(entry.value.expose_secret().to_owned()))
            } else {
                None
            }
        })
    }

    /// Wstawia lub nadpisuje sekret wraz z jego TTL.
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

    /// Usuwa pojedynczy wpis (np. po rotacji/unieważnieniu).
    pub fn remove(&self, key: &str) {
        let mut guard = self.inner.write().expect("cache lock poisoned");
        guard.remove(key);
    }

    /// Zwraca listę kluczy zbliżających się do wygaśnięcia (do odnowienia przez worker).
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

impl Drop for CacheEntry {
    fn drop(&mut self) {
        // SecretString już zeruje swój bufor przy Drop; to jawne przypomnienie
        // API dla przyszłych pól niebędących typami z automatycznym zeroize.
    }
}

/// Pomocnicza otoczka do jednorazowych, wrażliwych buforów bajtowych
/// (np. surowa odpowiedź z KMS przed deserializacją), z gwarancją zerowania.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveBuffer(pub Vec<u8>);
