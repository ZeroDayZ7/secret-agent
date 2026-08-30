use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "secret-agent",
    about = "Sidecar dystrybuujący sekrety z KMS przez UDS"
)]
pub struct AgentConfig {
    #[arg(
        long,
        env = "SECRET_AGENT_SOCKET_PATH",
        default_value = "/run/secret-agent/agent.sock"
    )]
    pub socket_path: PathBuf,

    #[arg(long, env = "SECRET_AGENT_KMS_URL")]
    pub kms_url: String,

    #[arg(
        long,
        env = "SECRET_AGENT_KMS_SECRETS_PATH",
        default_value = "/api/v1/agent/credentials/issue"
    )]
    pub kms_secrets_path: String,

    #[arg(long, env = "SECRET_AGENT_HMAC_KEY")]
    pub hmac_key: String,

    #[arg(long, env = "SECRET_AGENT_CLIENT_ID")]
    pub client_id: String,

    #[arg(long, env = "SECRET_AGENT_TARGET_SERVICE")]
    pub target_service: String,

    #[arg(long, env = "SECRET_AGENT_TARGET_TYPE")]
    pub target_type: String,

    #[arg(long, env = "SECRET_AGENT_RESOURCE")]
    pub resource: String,

    #[arg(long, env = "SECRET_AGENT_KMS_TIMEOUT_SECS", default_value_t = 10)]
    pub kms_timeout_secs: u64,

    #[arg(long, env = "SECRET_AGENT_DEFAULT_TTL_SECS", default_value_t = 2700)]
    pub default_ttl_secs: u64,

    #[arg(long, env = "SECRET_AGENT_POLL_INTERVAL_SECS", default_value_t = 15)]
    pub poll_interval_secs: u64,

    #[arg(
        long,
        env = "SECRET_AGENT_RENEWAL_LOOKAHEAD_SECS",
        default_value_t = 900
    )]
    pub renewal_lookahead_secs: u64,

    #[arg(long, env = "SECRET_AGENT_BACKOFF_BASE_MS", default_value_t = 500)]
    pub backoff_base_ms: u64,

    #[arg(long, env = "SECRET_AGENT_BACKOFF_MAX_MS", default_value_t = 30_000)]
    pub backoff_max_ms: u64,

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

fn parse_octal_mode(s: &str) -> Result<u32, String> {
    let trimmed = s.trim();
    let clean = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    u32::from_str_radix(clean, 8).map_err(|e| format!("nieprawidłowy format ósemkowy: {e}"))
}
