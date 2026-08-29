use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// Konfiguracja agenta, parsowana z CLI oraz zmiennych środowiskowych (prefiks SECRET_AGENT_).
#[derive(Parser, Debug, Clone)]
#[command(
    name = "secret-agent",
    about = "Sidecar dystrybuujący sekrety z KMS przez UDS"
)]
pub struct AgentConfig {
    /// Ścieżka do gniazda Unix Domain Socket udostępnianego lokalnym kontenerom.
    #[arg(
        long,
        env = "SECRET_AGENT_SOCKET_PATH",
        default_value = "/run/secret-agent/agent.sock"
    )]
    pub socket_path: PathBuf,

    /// Adres bazowy serwera KMS.
    #[arg(long, env = "SECRET_AGENT_KMS_URL")]
    pub kms_url: String,

    /// Ścieżka REST API w KMS do pobierania sekretów.
    #[arg(
        long,
        env = "SECRET_AGENT_KMS_SECRETS_PATH",
        default_value = "/api/v1/agent/credentials/issue"
    )]
    pub kms_secrets_path: String,

    /// Ścieżka do tokenu ServiceAccount montowanego przez Kubernetes.
    #[arg(
        long,
        env = "SECRET_AGENT_SA_TOKEN_PATH",
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )]
    pub sa_token_path: PathBuf,

    /// Identyfikator poda/aplikacji używany przy autoryzacji w KMS.
    #[arg(long, env = "SECRET_AGENT_CLIENT_ID")]
    pub client_id: String,

    /// Timeout dla zapytania HTTP do KMS w sekundach (domyślnie 10 s).
    #[arg(long, env = "SECRET_AGENT_KMS_TIMEOUT_SECS", default_value_t = 10)]
    pub kms_timeout_secs: u64,

    /// Domyślny TTL sekretów, gdy KMS go nie zwróci (2700 sekund = 45 minut).
    #[arg(long, env = "SECRET_AGENT_DEFAULT_TTL_SECS", default_value_t = 2700)]
    pub default_ttl_secs: u64,

    /// Interwał cyklicznego sprawdzania cache (15 sekund).
    #[arg(long, env = "SECRET_AGENT_POLL_INTERVAL_SECS", default_value_t = 15)]
    pub poll_interval_secs: u64,

    /// Okno wyprzedzenia przed wygaśnięciem kwalifikujące sekret do odnowienia (900 sekund = 15 minut).
    #[arg(
        long,
        env = "SECRET_AGENT_RENEWAL_LOOKAHEAD_SECS",
        default_value_t = 900
    )]
    pub renewal_lookahead_secs: u64,

    /// Minimalny odstęp między próbami ponowienia po błędzie (backoff bazowy, ms).
    #[arg(long, env = "SECRET_AGENT_BACKOFF_BASE_MS", default_value_t = 500)]
    pub backoff_base_ms: u64,

    /// Maksymalny odstęp backoffu (ms).
    #[arg(long, env = "SECRET_AGENT_BACKOFF_MAX_MS", default_value_t = 30_000)]
    pub backoff_max_ms: u64,

    /// Uprawnienia dla pliku socketu UDS w formacie ósemkowym (domyślnie 0o660).
    #[arg(
        long,
        env = "SECRET_AGENT_SOCKET_MODE",
        default_value_t = 0o660,
        value_parser = parse_octal_mode
    )]
    pub socket_mode: u32,
}

impl AgentConfig {
    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.default_ttl_secs)
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs)
    }

    pub fn renewal_lookahead(&self) -> Duration {
        Duration::from_secs(self.renewal_lookahead_secs)
    }

    pub fn kms_timeout(&self) -> Duration {
        Duration::from_secs(self.kms_timeout_secs)
    }

    pub fn secrets_full_url(&self) -> String {
        let base = self.kms_url.trim_end_matches('/');
        let path = if self.kms_secrets_path.starts_with('/') {
            self.kms_secrets_path.clone()
        } else {
            format!("/{}", self.kms_secrets_path)
        };
        format!("{}{}", base, path)
    }
}

/// Parsuje zapis praw dostępu (np. "0o660", "0660" lub "660") na wartość liczbową u32 w systemie ósemkowym.
fn parse_octal_mode(s: &str) -> Result<u32, String> {
    let trimmed = s.trim();
    let clean = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    u32::from_str_radix(clean, 8).map_err(|e| format!("nieprawidłowy format ósemkowy: {e}"))
}
