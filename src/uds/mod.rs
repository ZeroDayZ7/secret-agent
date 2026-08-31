use std::path::Path;
use std::sync::Arc;

use crate::cache::SecretCache;
use crate::config::AgentConfig;

#[cfg(unix)]
use serde::{Deserialize, Serialize};

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct BootstrapRequest {
    target_service: String,
    services: Vec<String>,
}

#[cfg(unix)]
#[derive(Debug, Serialize, Default)]
struct FullBootstrapResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    postgres: Option<rmpv::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redis: Option<rmpv::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minio: Option<rmpv::Value>,
}

#[cfg(unix)]
pub async fn serve(cache: Arc<SecretCache>, config: AgentConfig) -> std::io::Result<()> {
    use tokio::net::UnixListener;

    prepare_socket_dir(&config.socket_path)?;
    cleanup_socket(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path)?;
    set_socket_permissions(&config.socket_path, config.socket_mode)?;

    tracing::info!(path = %config.socket_path.display(), "🟢 Serwer UDS IPC nasłuchuje na gnieździe (Length-Delimited Frame Mode)");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let conn_cache = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, conn_cache).await {
                tracing::warn!(error = %err, "⚠️ Błąd podczas obsługi połączenia UDS IPC");
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve(_cache: Arc<SecretCache>, _config: AgentConfig) -> std::io::Result<()> {
    tracing::warn!("⚠️ Serwer UDS nie jest wspierany natywnie na systemie Windows.");
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    cache: Arc<SecretCache>,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    // 1. Odczyt długości ramki (4 bajty u32 BigEndian)
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return Ok(());
    }
    let req_len = u32::from_be_bytes(len_buf) as usize;

    if req_len == 0 || req_len > 65_536 {
        tracing::warn!(size = req_len, "Nieprawidłowy rozmiar ramki żądania UDS");
        return send_frame(&mut stream, &[]).await;
    }

    // 2. Odczyt surowego payloadu polecenia
    let mut req_buf = vec![0u8; req_len];
    stream.read_exact(&mut req_buf).await?;

    // 3. Obsługa komend binarnego protokołu IPC
    if req_buf.starts_with(b"BOOTSTRAP ") {
        let payload_bytes = &req_buf[10..];
        let response_bytes = handle_bootstrap(payload_bytes, &cache);
        return send_frame(&mut stream, &response_bytes).await;
    }

    if req_buf.starts_with(b"REFRESH ") {
        let command_str = String::from_utf8_lossy(&req_buf[8..]);
        let parts: Vec<&str> = command_str.split_whitespace().collect();
        if parts.len() >= 2 {
            let key = format!("{}_{}", parts[0], parts[1]);
            if let Some(secret) = cache.get(&key) {
                return send_frame(&mut stream, &secret).await;
            }
        }
        return send_frame(&mut stream, &[]).await;
    }

    // Fallback: traktuj jako bezpośrednie odpytanie o klucz
    let cache_key = match std::str::from_utf8(&req_buf) {
        Ok(k) => k.trim(),
        Err(_) => return send_frame(&mut stream, &[]).await,
    };

    match cache.get(cache_key) {
        Some(secret_bytes) => send_frame(&mut stream, &secret_bytes).await,
        None => send_frame(&mut stream, &[]).await,
    }
}

#[cfg(unix)]
fn handle_bootstrap(payload: &[u8], cache: &SecretCache) -> Vec<u8> {
    let req: BootstrapRequest = match rmp_serde::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Błąd deserializacji payloadu BOOTSTRAP z MessagePack");
            return Vec::new();
        }
    };

    let mut response = FullBootstrapResponse::default();

    for svc in &req.services {
        let key = format!("{}_{}", req.target_service, svc);
        if let Some(secret_bytes) = cache.get(&key) {
            if let Ok(value) = rmp_serde::from_slice::<rmpv::Value>(&secret_bytes) {
                match svc.as_str() {
                    "postgres" => response.postgres = Some(value),
                    "redis" => response.redis = Some(value),
                    "minio" => response.minio = Some(value),
                    _ => {}
                }
            }
        }
    }

    rmp_serde::to_vec(&response).unwrap_or_default()
}

#[cfg(unix)]
async fn send_frame(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let len = payload.len() as u32;
    let len_bytes = len.to_be_bytes();

    stream.write_all(&len_bytes).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
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
