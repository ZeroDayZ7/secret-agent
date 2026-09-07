use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, watch};

use crate::cache::SecretCache;
use crate::config::AgentConfig;
use crate::kms::KmsClient;
use crate::manifest::ServiceManifest;
use crate::state::{AgentState, AgentStateMachine};
use std::collections::HashMap;

const REFRESH_CONCURRENCY: usize = 4;

pub async fn run_renewal_loop(
    cache: Arc<SecretCache>,
    state: Arc<AgentStateMachine>,
    kms_client: Arc<KmsClient>,
    config: AgentConfig,
    manifest: Arc<ServiceManifest>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_millis(config.backoff_base_ms);
    let backoff_max = Duration::from_millis(config.backoff_max_ms);

    // -------------------------------------------------------------------------
    // 1. FAZA BOOTSTRAPU (Wykonuje się tylko RAZ przy starcie)
    // -------------------------------------------------------------------------
    // Track per-credential bootstrap status so we don't re-request already fetched secrets
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum CredentialStatus {
        Pending,
        Fetched,
        Failed,
    }

    let mut statuses: HashMap<String, CredentialStatus> = manifest
        .credentials
        .iter()
        .map(|c| (c.name.clone(), CredentialStatus::Pending))
        .collect();

    loop {
        tracing::info!(items_count = manifest.credentials.len(), "📦 Pobieram pełny zestaw poświadczeń z KMS (Batch Bootstrap)...");

        // First try batch request (fast path)
        match kms_client.fetch_batch_bootstrap(&manifest.credentials).await {
            Ok(secrets) if !secrets.is_empty() && secrets.len() == manifest.credentials.len() => {
                // Got all secrets in batch — success
                let count = secrets.len();
                cache.update_all(secrets);
                cache.purge_expired();

                tracing::info!(loaded_secrets = count, expected = manifest.credentials.len(), "✅ Wszystkie poświadczenia zostały pomyślnie załadowane do cache");

                if let Err(err) = state.transition(AgentState::Ready) {
                    tracing::error!(error = %err, "❌ Nie udało się przejść do stanu Ready");
                } else {
                    tracing::info!("🟢 Agent gotowy – obsługa gniazda UDS aktywna");
                }

                break;
            }
            Ok(secrets) => {
                // Partial success: update statuses for fetched items
                tracing::warn!(loaded = secrets.len(), expected = manifest.credentials.len(), "⚠️ Otrzymano częściowy wynik batchowy z KMS");
                for (k, v) in secrets.into_iter() {
                    tracing::info!(credential = %k, "📥 Zaktualizowano pojedynczy sekret z częściowego wyniku batchowego");
                    cache.update_single(k.clone(), v);
                    statuses.insert(k, CredentialStatus::Fetched);
                }
                cache.purge_expired();
                state.set(AgentState::Degraded);
            }
            Err(err) => {
                tracing::warn!(error = %err, "❌ Błąd batchowego pobierania od KMS — spróbuję pobrać pozycje indywidualnie");
                state.set(AgentState::Degraded);

                // Try fetching missing items individually
                for credential in &manifest.credentials {
                    let name = credential.name.clone();
                    if statuses.get(&name) == Some(&CredentialStatus::Fetched) {
                        continue; // already fetched
                    }

                    match kms_client.fetch_single_secret(credential).await {
                        Ok(secret) => {
                            tracing::info!(credential = %name, "[Bootstrap] Pobrano pojedynczy sekret");
                            cache.update_single(name.clone(), secret);
                            statuses.insert(name.clone(), CredentialStatus::Fetched);
                        }
                        Err(e) => {
                            tracing::warn!(credential = %name, error = %e, "[Bootstrap] Nie udało się pobrać pojedynczego sekretu — oznaczam jako Failed");
                            statuses.insert(name.clone(), CredentialStatus::Failed);
                        }
                    }
                }

                // If all items fetched -> success
                if statuses.values().all(|s| *s == CredentialStatus::Fetched) {
                    tracing::info!(loaded = statuses.len(), "✅ Wszystkie poświadczenia pobrane indywidualnie — kończę bootstrap");
                    if let Err(err) = state.transition(AgentState::Ready) {
                        tracing::error!(error = %err, "❌ Nie udało się przejść do stanu Ready");
                    } else {
                        tracing::info!("🟢 Agent gotowy – obsługa gniazda UDS aktywna");
                    }
                    break;
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {},
            _ = shutdown_rx.changed() => {
                tracing::info!("Shutdown requested during bootstrap backoff");
                return;
            }
        }
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
        tokio::select! {
            _ = poll_timer.tick() => {},
            _ = shutdown_rx.changed() => {
                tracing::info!("Shutdown requested during poll interval");
                break;
            }
        }

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
    kms_client: &Arc<KmsClient>,
    manifest: &Arc<ServiceManifest>,
) -> Result<(), crate::kms::KmsError> {
    let sem = Arc::new(Semaphore::new(REFRESH_CONCURRENCY));
    let mut handles = Vec::new();

    let owned_keys: Vec<String> = expiring_keys.to_vec();
    for key in owned_keys {
        let cache = Arc::clone(cache);
        let kms = Arc::clone(kms_client);
        let manifest = Arc::clone(manifest);
        let sem = Arc::clone(&sem);

        let handle = tokio::spawn(async move {
            // Acquire permit to bound concurrency
            let _permit = sem.acquire().await.expect("semaphore closed");

            if let Some(credential) = manifest.credentials.iter().find(|c| c.name == key.as_str()) {
                match kms.fetch_single_secret(credential).await {
                    Ok(secret) => {
                        tracing::info!(key = %secret.key, "Odebrano odświeżony sekret");
                        cache.update_single(secret.key.clone(), secret);
                        Ok(())
                    }
                    Err(err) => {
                        tracing::error!(error = %err, key = %key, "Błąd odnowienia pojedynczego sekretu");
                        Err(err)
                    }
                }
            } else {
                tracing::warn!(key = %key, "Specyfikacja credential nie znaleziona w manifeście");
                Ok(())
            }
        });

        handles.push(handle);
    }

    // Wait for all tasks and collect errors (but don't short-circuit on first failure)
    let mut last_err: Option<crate::kms::KmsError> = None;
    for h in handles {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => last_err = Some(e),
            Err(join_err) => tracing::error!(?join_err, "Task odświeżania panikował"),
        }
    }

    if let Some(e) = last_err {
        Err(e)
    } else {
        Ok(())
    }
}
