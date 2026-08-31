use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use zeroize::Zeroizing;

use crate::cache::SecretCache;
use crate::config::AgentConfig;

#[cfg(unix)]
pub async fn serve(cache: Arc<SecretCache>, config: AgentConfig) -> std::io::Result<()> {
    prepare_socket_dir(&config.socket_path)?;
    cleanup_socket(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path)?;
    set_socket_permissions(&config.socket_path, config.socket_mode)?;

    tracing::info!(path = %config.socket_path.display(), "🟢 Serwer UDS IPC nasłuchuje na gnieździe (Raw Binary Mode)");

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
async fn handle_connection(mut stream: UnixStream, cache: Arc<SecretCache>) -> std::io::Result<()> {
    // 1. Odczyt długości nazwy klucza (1 bajt długości + nazwa klucza)
    let mut key_len_buf = [0u8; 1];
    if stream.read_exact(&mut key_len_buf).await.is_err() {
        return Ok(());
    }

    let key_len = key_len_buf[0] as usize;
    let mut key_buf = vec![0u8; key_len];
    stream.read_exact(&mut key_buf).await?;

    let cache_key = match std::str::from_utf8(&key_buf) {
        Ok(k) => k,
        Err(_) => return send_frame(&mut stream, &[]).await, // Pusta ramka na błąd
    };

    // 2. Pobranie bajtów z cache i wysłanie jako [u32 BigEndian Length][Raw Payload Bytes]
    match cache.get(cache_key) {
        Some(secret_bytes) => {
            send_frame(&mut stream, &secret_bytes).await?;
        }
        None => {
            send_frame(&mut stream, &[]).await?;
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn send_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
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
