use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use secrecy::ExposeSecret;
#[cfg(unix)]
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::cache::SecretCache;
use crate::config::AgentConfig;

#[cfg(unix)]
const MAX_REQUEST_BYTES: usize = 8192;

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct BootstrapPayload {
    target_service: String,
    services: Vec<String>,
}

#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize, Default)]
struct PostgresCredentials {
    username: String,
    password: String,
}

#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize, Default)]
struct RedisCredentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    password: String,
}

#[cfg(unix)]
#[derive(Debug, Serialize, Deserialize, Default)]
struct MinioCredentials {
    access_key: String,
    secret_key: String,
}

#[cfg(unix)]
#[derive(Debug, Serialize, Default)]
struct FullBootstrapResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    postgres: Option<PostgresCredentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redis: Option<RedisCredentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minio: Option<MinioCredentials>,
}

#[cfg(unix)]
pub async fn serve(cache: Arc<SecretCache>, config: AgentConfig) -> std::io::Result<()> {
    prepare_socket_dir(&config.socket_path)?;
    cleanup_socket(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path)?;
    set_socket_permissions(&config.socket_path, config.socket_mode)?;

    tracing::info!(path = %config.socket_path.display(), "🟢 Serwer UDS nasłuchuje na gnieździe");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let conn_cache = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, conn_cache).await {
                tracing::warn!(error = %err, "⚠️ Błąd podczas obsługi połączenia UDS");
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve(_cache: Arc<SecretCache>, _config: AgentConfig) -> std::io::Result<()> {
    tracing::warn!(
        "⚠️ Serwer UDS nie jest wspierany natywnie na systemie Windows. Uruchom aplikację w kontenerze Docker / WSL."
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(mut stream: UnixStream, cache: Arc<SecretCache>) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    let line = match std::str::from_utf8(&buf[..n]) {
        Ok(s) => s.trim(),
        Err(_) => {
            return send_err(&mut stream, "invalid_utf8").await;
        }
    };

    if line.starts_with("BOOTSTRAP ") {
        let json_part = line.trim_start_matches("BOOTSTRAP ").trim();
        let payload: BootstrapPayload = match serde_json::from_str(json_part) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "Nieprawidłowy JSON w komendzie BOOTSTRAP");
                return send_err(&mut stream, "invalid_bootstrap_json").await;
            }
        };

        let mut resp = FullBootstrapResponse::default();

        for srv in &payload.services {
            match srv.as_str() {
                "postgres" => {
                    let key = format!("{}_postgres", payload.target_service);
                    if let Some(sec) = cache.get(&key) {
                        if let Ok(creds) =
                            serde_json::from_str::<PostgresCredentials>(sec.expose_secret())
                        {
                            resp.postgres = Some(creds);
                        }
                    }
                }
                "redis" => {
                    let key = format!("{}_redis", payload.target_service);
                    if let Some(sec) = cache.get(&key) {
                        if let Ok(creds) =
                            serde_json::from_str::<RedisCredentials>(sec.expose_secret())
                        {
                            resp.redis = Some(creds);
                        }
                    }
                }
                "minio" => {
                    let key = format!("{}_minio", payload.target_service);
                    if let Some(sec) = cache.get(&key) {
                        if let Ok(creds) =
                            serde_json::from_str::<MinioCredentials>(sec.expose_secret())
                        {
                            resp.minio = Some(creds);
                        }
                    }
                }
                _ => {}
            }
        }

        let resp_json = serde_json::to_string(&resp)?;
        let out = format!("OK {}\n", resp_json);
        stream.write_all(out.as_bytes()).await?;
    } else if line.starts_with("REFRESH ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return send_err(&mut stream, "invalid_refresh_args").await;
        }

        let target_service = parts[1];
        let resource = parts[2];
        let cache_key = format!("{}_{}", target_service, resource);

        match cache.get(&cache_key) {
            Some(sec) => {
                let out = format!("OK {}\n", sec.expose_secret());
                stream.write_all(out.as_bytes()).await?;
            }
            None => {
                return send_err(&mut stream, "secret_not_found").await;
            }
        }
    } else {
        return send_err(&mut stream, "unknown_command").await;
    }

    stream.flush().await?;
    Ok(())
}

#[cfg(unix)]
async fn send_err(stream: &mut UnixStream, msg: &str) -> std::io::Result<()> {
    let out = format!("ERR {}\n", msg);
    stream.write_all(out.as_bytes()).await?;
    stream.flush().await
}

#[cfg(unix)]
fn prepare_socket_dir(socket_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(socket_path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(socket_path, permissions)
}

pub fn cleanup_socket(socket_path: &Path) {
    if let Err(err) = std::fs::remove_file(socket_path) {
        match err.kind() {
            std::io::ErrorKind::NotFound => {}
            _ => tracing::warn!(error = %err, "nie udało się usunąć pliku socketu"),
        }
    }
}
