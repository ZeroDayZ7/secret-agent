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

    // -------------------------------------------------------------------------
    // 1. FAZA BOOTSTRAPU (Wykonuje się tylko RAZ przy starcie)
    // -------------------------------------------------------------------------

    loop {
        tracing::info!(
            items_count = manifest.credentials.len(),
            "📦 Pobieram pełny zestaw poświadczeń z KMS (Batch Bootstrap)..."
        );
        tracing::debug!(
            items_count = manifest.credentials.len(),
            "📦 Pobieram pełny zestaw poświadczeń z KMS (Batch Bootstrap)..."
        );

        match kms_client
            .fetch_batch_bootstrap(&manifest.credentials)
            .await
        {
            Ok(secrets) if !secrets.is_empty() => {
                let count = secrets.len();
                cache.update_all(secrets);
                cache.purge_expired();

                tracing::info!(
                    loaded_secrets = count,
                    expected = manifest.credentials.len(),
                    "✅ Wszystkie poświadczenia zostały pomyślnie załadowane do cache"
                );

                if let Err(err) = state.transition(AgentState::Ready) {
                    tracing::error!(error = %err, "❌ Nie udało się przejść do stanu Ready");
                } else {
                    tracing::info!("🟢 Agent gotowy – obsługa gniazda UDS aktywna");
                }

                break; // Sukces bootstrapu – wyjście z pętli inicjalizacyjnej
            }
            Ok(_) => {
                tracing::warn!("⚠️ KMS zwrócił pustą listę sekretów dla manifestu");
                state.set(AgentState::Degraded);
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    retry_in_ms = backoff.as_millis(),
                    "❌ Błąd pobierania pakietu startowego z KMS. Ponawiam próbę z backoffem..."
                );
                state.set(AgentState::Degraded);
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, backoff_max);
    }

    // -------------------------------------------------------------------------
    // 2. CYKLICZNE MONITOROWANIE (Sterowane zmienną SECRET_AGENT_POLL_INTERVAL_SECS)
    // -------------------------------------------------------------------------
    let poll_interval = config.poll_interval();
    tracing::info!(
        interval_secs = poll_interval.as_secs(),
        "⏱️ Uruchamiam cykliczne monitorowanie sekretów"
    );

    let mut poll_timer = tokio::time::interval(poll_interval);
    // Pomiń pierwsze natychmiastowe tyknięcie – dopiero co zrobiliśmy bootstrap w Fazie 1!
    poll_timer.tick().await;

    loop {
        // Czekamy pełny interwał (np. 86400s lub 10s w dev)
        poll_timer.tick().await;

        cache.purge_expired();

        let expiring = cache.keys_expiring_within(config.renewal_lookahead());

        if expiring.is_empty() {
            tracing::debug!("🔍 Brak sekretów wymagających odnowienia.");
            continue;
        }

        tracing::info!(
            count = expiring.len(),
            keys = ?expiring,
            "⚠️ Wykryto sekrety zbliżające się do wygaśnięcia. Odnawiam..."
        );

        if let Err(err) = state.transition(AgentState::Refreshing) {
            tracing::warn!(error = %err, "Nie udało się przejść w stan Refreshing");
        }

        match refresh_expiring(&expiring, &cache, &kms_client, &manifest).await {
            Ok(()) => {
                tracing::info!("✅ Pomyślnie odnowiono wygasające poświadczenia w KMS");
                let _ = state.transition(AgentState::Ready);
            }
            Err(err) => {
                tracing::warn!(error = %err, "❌ Błąd odnawiania sekretów");
                state.set(AgentState::Degraded);
            }
        }
    }
}

async fn refresh_expiring(
    expiring_keys: &[String],
    cache: &Arc<SecretCache>,
    kms_client: &KmsClient,
    manifest: &ServiceManifest,
) -> Result<(), crate::kms::KmsError> {
    for key in expiring_keys {
        if let Some(credential) = manifest.credentials.iter().find(|c| &c.name == key) {
            match kms_client.fetch_single_secret(credential).await {
                Ok(secret) => {
                    tracing::info!(key = %secret.key, "Odebrano odświeżony sekret");
                    cache.update_single(secret.key.clone(), secret); // POPRAWNE
                }
                Err(err) => tracing::error!(error = %err, key = %key, "Błąd odnowienia pojedynczego sekretu"),
            }
        }
    }
    Ok(())
}
