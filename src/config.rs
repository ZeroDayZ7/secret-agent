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

    /// Domyślny TTL sekretów, gdy KMS go nie zwróci (w sekundach).
    #[arg(long, env = "SECRET_AGENT_DEFAULT_TTL_SECS", default_value_t = 300)]
    pub default_ttl_secs: u64,

    /// Interwał cyklicznego odpytywania cache (w sekundach).
    #[arg(long, env = "SECRET_AGENT_POLL_INTERVAL_SECS", default_value_t = 15)]
    pub poll_interval_secs: u64,

    /// Okno czasowe przed wygaśnięciem sekretu kwalifikujące go do odnowienia (w sekundach).
    #[arg(
        long,
        env = "SECRET_AGENT_RENEWAL_LOOKAHEAD_SECS",
        default_value_t = 30
    )]
    pub renewal_lookahead_secs: u64,

    #[arg(long, env = "SECRET_AGENT_BACKOFF_BASE_MS", default_value_t = 500)]
    pub backoff_base_ms: u64,

    /// Maksymalny odstęp backoffu (ms).
    #[arg(long, env = "SECRET_AGENT_BACKOFF_MAX_MS", default_value_t = 30_000)]
    pub backoff_max_ms: u64,
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
