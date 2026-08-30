mod cache;
mod config;
mod kms;
mod uds;
mod worker;

use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cache::SecretCache;
use config::AgentConfig;

#[derive(thiserror::Error, Debug)]
pub enum AgentError {
    #[error("błąd konfiguracji: {0}")]
    Config(String),
    #[error("błąd KMS: {0}")]
    Kms(#[from] kms::KmsError),
    #[error("błąd UDS: {0}")]
    Uds(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let config = AgentConfig::parse();
    tracing::info!(socket_path = %config.socket_path.display(), "🚀 Startuje secret-agent w Rust");

    let cache: Arc<SecretCache> = Arc::new(SecretCache::new());
    let kms_client = kms::KmsClient::new(&config)?;

    let worker_cache = Arc::clone(&cache);
    let worker_handle = tokio::spawn(worker::run_renewal_loop(
        worker_cache,
        kms_client,
        config.clone(),
    ));

    let uds_cache = Arc::clone(&cache);
    let uds_handle = tokio::spawn(uds::serve(uds_cache, config.clone()));

    tokio::select! {
        _ = wait_for_shutdown_signal() => tracing::info!("🛑 Otrzymano sygnał wyłączenia, zamykam agenta"),
        res = worker_handle => {
            tracing::error!(?res, "Worker zakończył działanie nieoczekiwanie");
        }
        res = uds_handle => {
            tracing::error!(?res, "Serwer UDS zakończył działanie nieoczekiwanie");
        }
    }

    uds::cleanup_socket(&config.socket_path);
    tracing::info!("Secret-agent został zatrzymany");
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("nie udało się zarejestrować SIGTERM");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("nie udało się zarejestrować SIGINT");

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Odebrano SIGTERM"),
            _ = sigint.recv() => tracing::info!("Odebrano SIGINT"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("nie udało się zarejestrować sygnału Ctrl+C");
    }
}
