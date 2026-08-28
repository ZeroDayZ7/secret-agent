use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// Konfiguracja agenta, parsowana z CLI oraz zmiennych środowiskowych (prefiks SECRET_AGENT_).
#[derive(Parser, Debug, Clone)]
#[command(name = "secret-agent", about = "Sidecar dystrybuujący sekrety z KMS przez UDS")]
pub struct AgentConfig {
    /// Ścieżka do gniazda Unix Domain Socket udostępnianego lokalnym kontenerom.
    #[arg(long, env = "SECRET_AGENT_SOCKET_PATH", default_value = "/run/secret-agent/agent.sock")]
    pub socket_path: PathBuf,

    /// Adres bazowy serwera KMS.
    #[arg(long, env = "SECRET_AGENT_KMS_URL")]
    pub kms_url: String,

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

    /// Minimalny odstęp między próbami ponowienia po błędzie (backoff bazowy, ms).
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
}
