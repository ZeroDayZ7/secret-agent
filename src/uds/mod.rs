use std::path::Path;
use std::sync::Arc;

use crate::cache::SecretCache;
use crate::config::AgentConfig;

#[cfg(unix)]
use secrecy::ExposeSecret;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(unix)]
const MAX_REQUEST_BYTES: usize = 4096;

/// Uruchamia serwer UDS (dla Unix) lub mocka (dla Windows).
#[cfg(unix)]
pub async fn serve(cache: Arc<SecretCache>, config: AgentConfig) -> std::io::Result<()> {
    prepare_socket_dir(&config.socket_path)?;
    cleanup_socket(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path)?;
    set_socket_permissions(&config.socket_path, config.socket_mode)?;

    tracing::info!(path = %config.socket_path.display(), "nasłuchuję na UDS");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let conn_cache = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, conn_cache).await {
                tracing::warn!(error = %err, "błąd obsługi połączenia UDS");
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve(_cache: Arc<SecretCache>, _config: AgentConfig) -> std::io::Result<()> {
    tracing::warn!(
        "Unix Domain Sockets nie są wspierane natywnie na tej platformie (Windows). UDS Server wyłączony w trybie deweloperskim."
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(mut stream: UnixStream, cache: Arc<SecretCache>) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let n = stream.read(&mut buf).await?;

    // 1. Odrzucamy połączenia bez danych
    if n == 0 {
        return Ok(());
    }

    // 2. Weryfikujemy czy wejście jest poprawnym UTF-8
    let raw_str = match std::str::from_utf8(&buf[..n]) {
        Ok(s) => s.trim(),
        Err(_) => {
            stream.write_all(b"ERR invalid_utf8\n").await?;
            stream.flush().await?;
            return Ok(());
        }
    };

    // 3. Walidacja: klucz nie może być pusty ani zawierać znaków sterujących (np. \0, \r, \n)
    if raw_str.is_empty() || raw_str.chars().any(|c| c.is_control()) {
        stream.write_all(b"ERR invalid_key\n").await?;
        stream.flush().await?;
        return Ok(());
    }

    // 4. Pobranie z cache
    match cache.get(raw_str) {
        Some(secret) => {
            let payload = format!("OK {}\n", secret.expose_secret());
            stream.write_all(payload.as_bytes()).await?;
        }
        None => {
            stream.write_all(b"ERR not_found\n").await?;
        }
    }

    stream.flush().await?;
    Ok(())
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