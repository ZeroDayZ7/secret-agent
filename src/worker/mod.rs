use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::cache::SecretCache;
use crate::config::AgentConfig;
use crate::kms::KmsClient;
use crate::manifest::ServiceManifest;
use crate::state::{AgentState, AgentStateMachine};

pub async fn run_renewal_loop(
    cache: Arc<SecretCache>,
    state: Arc<AgentStateMachine>,
    kms_client: KmsClient,
    config: AgentConfig,
    manifest: ServiceManifest,
) {
    let mut backoff = Duration::from_millis(config.backoff_base_ms);
    let backoff_max = Duration::from_millis(config.backoff_max_ms);

    tracing::info!("📥 Pobieram początkowy zestaw poświadczeń z KMS...");
    if let Err(err) = refresh_all(&cache, &state, &kms_client, &manifest, &config).await {
        tracing::error!(error = %err, "❌ Wstępne pobranie sekretów z KMS nie powiodło się");
        state.set(AgentState::Degraded);
    } else {
        tracing::info!("✅ Początkowe poświadczenia zostały pomyślnie załadowane do cache agenta");
        let _ = state.transition(AgentState::Ready);
    }

    let mut poll_timer = tokio::time::interval(config.poll_interval());

    loop {
        tokio::select! {
            _ = poll_timer.tick() => {
                cache.purge_expired();
                let expiring = cache.keys_expiring_within(config.renewal_lookahead());

                if expiring.is_empty() {
                    continue;
                }

                tracing::info!(
                    count = expiring.len(),
                    "⚠️ Wykryto sekrety zbliżające się do wygaśnięcia. Odnawiam..."
                );

                state.set(AgentState::Refreshing);
                match refresh_all(&cache, &state, &kms_client, &manifest, &config).await {
                    Ok(()) => {
                        tracing::info!("✅ Pomyślnie odnowiono poświadczenia z KMS");
                        let _ = state.transition(AgentState::Ready);
                        backoff = Duration::from_millis(config.backoff_base_ms);
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            backoff_ms = backoff.as_millis(),
                            "❌ Ponawiam próbę z exponential backoff"
                        );
                        state.set(AgentState::Degraded);
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, backoff_max);
                    }
                }
            }
        }
    }
}

async fn refresh_all(
    cache: &Arc<SecretCache>,
    state: &Arc<AgentStateMachine>,
    kms_client: &KmsClient,
    manifest: &ServiceManifest,
    config: &AgentConfig,
) -> Result<(), crate::kms::KmsError> {
    let mut next_snapshot = HashMap::new();
    for credential in &manifest.credentials {
        let secret = kms_client.fetch_single_secret(credential).await?;
        next_snapshot.insert(secret.key.clone(), secret);
    }

    if next_snapshot.is_empty() {
        state.set(AgentState::Degraded);
        return Err(crate::kms::KmsError::Hmac(
            "brak poświadczeń zwróconych przez KMS dla manifestu".to_string(),
        ));
    }

    cache.update_all(next_snapshot);
    cache.purge_expired();
    if cache.values().is_empty() {
        state.set(AgentState::Degraded);
        return Err(crate::kms::KmsError::Hmac(
            "poświadczenia z KMS nie mogły zostać zapisane do cache".to_string(),
        ));
    }

    let _ = config;
    Ok(())
}
