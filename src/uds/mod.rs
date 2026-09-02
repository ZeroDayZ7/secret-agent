use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::collections::HashMap;

use crate::cache::SecretCache;
use crate::config::AgentConfig;
use crate::state::AgentStateMachine;

#[cfg(unix)]
pub async fn serve(
    cache: Arc<SecretCache>,
    state: Arc<AgentStateMachine>,
    config: AgentConfig,
) -> std::io::Result<()> {
    use tokio::net::UnixListener;

    prepare_socket_dir(&config.socket_path)?;
    cleanup_socket(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path)?;
    set_socket_permissions(&config.socket_path, config.socket_mode)?;

    tracing::info!(path = %config.socket_path.display(), "🟢 Serwer UDS IPC nasłuchuje na gnieździe");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let conn_cache = Arc::clone(&cache);
        let conn_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, conn_cache, conn_state).await {
                tracing::warn!(error = %err, "⚠️ Błąd podczas obsługi połączenia UDS IPC");
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve(
    _cache: Arc<SecretCache>,
    _state: Arc<AgentStateMachine>,
    _config: AgentConfig,
) -> std::io::Result<()> {
    tracing::warn!("⚠️ Serwer UDS nie jest wspierany natywnie na systemie Windows.");
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    cache: Arc<SecretCache>,
    state: Arc<AgentStateMachine>,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return Ok(());
    }
    let req_len = u32::from_be_bytes(len_buf) as usize;

    if req_len == 0 || req_len > 65_536 {
        tracing::warn!(size = req_len, "Nieprawidłowy rozmiar ramki żądania UDS");
        return send_frame(&mut stream, &[]).await;
    }

    let mut req_buf = vec![0u8; req_len];
    stream.read_exact(&mut req_buf).await?;

    if !state.is_uds_accepted() {
        return send_frame(&mut stream, &[]).await;
    }

    if req_buf.starts_with(b"BOOTSTRAP ") {
        let payload_bytes = &req_buf[9..];
        let response_bytes = handle_bootstrap(payload_bytes, &cache);
        return send_frame(&mut stream, &response_bytes).await;
    }

    if req_buf.starts_with(b"GET ") {
        let name = std::str::from_utf8(&req_buf[4..])
            .unwrap_or_default()
            .trim();
        if let Some(secret) = cache.get(name) {
            return send_frame(&mut stream, &secret.value).await;
        }
        return send_frame(&mut stream, &[]).await;
    }

    let cache_key = match std::str::from_utf8(&req_buf) {
        Ok(k) => k.trim(),
        Err(_) => return send_frame(&mut stream, &[]).await,
    };

    match cache.get(cache_key) {
        Some(secret) => send_frame(&mut stream, &secret.value).await,
        None => send_frame(&mut stream, &[]).await,
    }
}

#[cfg(unix)]
fn handle_bootstrap(payload: &[u8], cache: &SecretCache) -> Vec<u8> {
    let requested_names: Vec<String> = match rmp_serde::from_slice::<Vec<String>>(payload) {
        Ok(names) => names,
        Err(_) => Vec::new(),
    };

    let snapshot = cache.values();
    let response: HashMap<String, rmpv::Value> = snapshot
        .into_iter()
        .filter(|(name, _)| {
            requested_names.is_empty() || requested_names.iter().any(|item| item == name)
        })
        .map(|(name, secret)| {
            let value = rmp_serde::from_slice::<rmpv::Value>(&secret.value)
                .unwrap_or(rmpv::Value::Binary(secret.value.to_vec()));
            (name, value)
        })
        .collect();

    rmp_serde::to_vec_named(&response).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::cache::SecretCache;
    use crate::kms::SecretPayload;
    use crate::state::{AgentState, AgentStateMachine};

    #[test]
    fn generic_messagepack_payload_roundtrips() {
        let payload = rmpv::Value::Map(vec![
            (
                rmpv::Value::String("username".into()),
                rmpv::Value::String("alice".into()),
            ),
            (
                rmpv::Value::String("password".into()),
                rmpv::Value::Binary(b"s3cr3t".to_vec()),
            ),
        ]);
        let bytes = rmp_serde::to_vec(&payload).unwrap();
        let decoded: rmpv::Value = rmp_serde::from_slice(&bytes).unwrap();
        assert!(decoded.as_map().is_some());
    }

    #[test]
    fn uds_state_rejects_not_ready_connections() {
        let state = Arc::new(AgentStateMachine::new());
        assert!(!state.is_uds_accepted());
        state.set(AgentState::Ready);
        assert!(state.is_uds_accepted());
    }

    #[test]
    fn cache_snapshot_supports_generic_values() {
        let cache = SecretCache::new();
        let payload = SecretPayload {
            key: "postgres".to_string(),
            value: zeroize::Zeroizing::new(
                rmp_serde::to_vec(&rmpv::Value::String("secret".into())).unwrap(),
            ),
            ttl_secs: Some(120),
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(120)),
        };
        cache.update_all(HashMap::from([("postgres".to_string(), payload.clone())]));
        assert_eq!(cache.get("postgres").unwrap().key, "postgres");
    }
}