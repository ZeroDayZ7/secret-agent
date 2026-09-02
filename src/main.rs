mod cache;
mod config;
mod kms;
mod logger;
mod manifest;
mod state;
mod uds;
mod worker;

use std::sync::Arc;

use clap::Parser;

use cache::SecretCache;
use config::AgentConfig;
use state::AgentState;
use state::AgentStateMachine;

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
    // 1. Parsowanie konfiguracji CLI / ENV
    let config = AgentConfig::parse();

    // 2. Inicjalizacja formatowania logów na podstawie zaktualizowanej konfiguracji
    logger::init_logging(&config.log_config());

    tracing::info!(socket_path = %config.socket_path.display(), "🚀 Startuje secret-agent w Rust");

    let manifest = config.load_manifest().map_err(AgentError::Config)?;
    tracing::info!(service = %manifest.service.name, credentials = manifest.credentials.len(), "📦 Załadowano manifest credentialów");

    let cache: Arc<SecretCache> = Arc::new(SecretCache::new());
    let state = Arc::new(AgentStateMachine::new());
    state
        .transition(AgentState::Bootstrapping)
        .map_err(AgentError::Config)?;

    let kms_client = kms::KmsClient::new(&config)?;

    let worker_cache = Arc::clone(&cache);
    let worker_state = Arc::clone(&state);
    let worker_handle = tokio::spawn(worker::run_renewal_loop(
        worker_cache,
        worker_state,
        kms_client,
        config.clone(),
        manifest.clone(),
    ));

    let uds_cache = Arc::clone(&cache);
    let uds_state = Arc::clone(&state);
    let uds_handle = tokio::spawn(uds::serve(uds_cache, uds_state, config.clone()));

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
