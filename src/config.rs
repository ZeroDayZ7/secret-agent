use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use zeroize::Zeroizing;

use crate::manifest::ServiceManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Json,
    Compact,
    Pretty,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub format: LogFormat,
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "secret-agent",
    about = "Sidecar dystrybuujący sekrety z KMS przez UDS"
)]
pub struct AgentConfig {
    #[arg(long, env = "LOG__FORMAT", default_value = "pretty", value_enum)]
    pub log_format: LogFormat,

    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,

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
    pub hmac_key: Option<String>,

    #[arg(long, env = "SECRET_AGENT_HMAC_KEY_FILE")]
    pub hmac_key_file: Option<PathBuf>,

    #[arg(long, env = "SECRET_AGENT_CLIENT_ID")]
    pub client_id: String,

    #[arg(long, env = "SECRET_AGENT_MANIFEST_PATH")]
    pub manifest_path: Option<PathBuf>,

    #[arg(long, env = "SECRET_AGENT_MANIFEST_CONTENT")]
    pub manifest_content: Option<String>,

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
    pub fn log_config(&self) -> LogConfig {
        LogConfig {
            level: self.log_level.clone(),
            format: self.log_format,
        }
    }

    /// Pobiera klucz HMAC: w pierwszej kolejności z pliku (SECRET_AGENT_HMAC_KEY_FILE),
    /// a w przypadku jego braku ze zmiennej środowiskowej (SECRET_AGENT_HMAC_KEY).
    pub fn get_hmac_key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        if let Some(ref path) = self.hmac_key_file {
            let bytes = fs::read(path).map_err(|e| {
                format!(
                    "nie udało się odczytać pliku klucza HMAC ({:?}): {}",
                    path, e
                )
            })?;

            // Obcinamy ewentualne znaki nowej linii (\n / \r\n) z końca pliku
            let trimmed = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
            let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);

            return Ok(Zeroizing::new(trimmed.to_vec()));
        }

        if let Some(ref key) = self.hmac_key {
            return Ok(Zeroizing::new(key.as_bytes().to_vec()));
        }

        Err(
            "Brak klucza HMAC: podaj SECRET_AGENT_HMAC_KEY_FILE lub SECRET_AGENT_HMAC_KEY"
                .to_string(),
        )
    }

    #[allow(dead_code)]
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

    pub fn load_manifest(&self) -> Result<ServiceManifest, String> {
        if let Some(ref content) = self.manifest_content {
            return serde_json::from_str::<ServiceManifest>(content)
                .or_else(|_| serde_yaml::from_str::<ServiceManifest>(content))
                .map_err(|e| {
                    format!("nie udało się odczytać manifestu z SECRET_AGENT_MANIFEST_CONTENT: {e}")
                });
        }

        if let Some(ref path) = self.manifest_path {
            let text = fs::read_to_string(path)
                .map_err(|e| format!("nie udało się odczytać pliku manifestu {:?}: {e}", path))?;
            return serde_yaml::from_str::<ServiceManifest>(&text)
                .or_else(|_| serde_json::from_str::<ServiceManifest>(&text))
                .map_err(|e| format!("nie udało się sparsować manifestu z pliku {:?}: {e}", path));
        }

        Err("brak manifestu: podaj --manifest-path lub SECRET_AGENT_MANIFEST_CONTENT".to_string())
    }
}

fn parse_octal_mode(s: &str) -> Result<u32, String> {
    let trimmed = s.trim();
    let clean = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    u32::from_str_radix(clean, 8).map_err(|e| format!("nieprawidłowy format ósemkowy: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ServiceManifest;

    #[test]
    fn parses_manifest_yaml_from_file() {
        let dir =
            std::env::temp_dir().join(format!("secret-agent-manifest-{}.yaml", std::process::id()));
        std::fs::write(
            &dir,
            r#"
service:
  name: auth
credentials:
  - name: postgres
    type: database
    resource: auth_db
  - name: redis
    type: redis
    resource: cache_cluster
"#,
        )
        .unwrap();

        let config = AgentConfig {
            log_format: LogFormat::Pretty,
            log_level: "debug".into(),
            socket_path: "/tmp/test.sock".into(),
            kms_url: "https://kms.example".into(),
            kms_secrets_path: "/api/v1/agent/credentials/issue".into(),
            hmac_key: None,
            hmac_key_file: None,
            client_id: "client-test".into(),
            manifest_path: Some(dir.clone()),
            manifest_content: None,
            kms_timeout_secs: 10,
            default_ttl_secs: 2700,
            poll_interval_secs: 15,
            renewal_lookahead_secs: 900,
            backoff_base_ms: 500,
            backoff_max_ms: 30000,
            socket_mode: 0o660,
        };

        let manifest = config.load_manifest().unwrap();
        assert_eq!(manifest.service.name, "auth");
        assert_eq!(manifest.credentials.len(), 2);
        assert_eq!(manifest.credentials[0].name, "postgres");

        let _ = std::fs::remove_file(dir);
    }

    #[test]
    fn parses_manifest_json_from_env_content() {
        let config = AgentConfig {
            log_format: LogFormat::Json,
            log_level: "info".into(),
            socket_path: "/tmp/test.sock".into(),
            kms_url: "https://kms.example".into(),
            kms_secrets_path: "/api/v1/agent/credentials/issue".into(),
            hmac_key: None,
            hmac_key_file: None,
            client_id: "client-test".into(),
            manifest_path: None,
            manifest_content: Some(
                r#"{"service":{"name":"auth"},"credentials":[{"name":"postgres","type":"database","resource":"auth_db"}]}"#
                    .to_string(),
            ),
            kms_timeout_secs: 10,
            default_ttl_secs: 2700,
            poll_interval_secs: 15,
            renewal_lookahead_secs: 900,
            backoff_base_ms: 500,
            backoff_max_ms: 30000,
            socket_mode: 0o660,
        };

        let manifest: ServiceManifest = config.load_manifest().unwrap();
        assert_eq!(manifest.credentials[0].r#type, "database");
    }
}
