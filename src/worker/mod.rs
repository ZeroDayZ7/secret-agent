use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;

use crate::cache::SecretCache;
use crate::config::AgentConfig;
use crate::kms::KmsClient;

/// Główna pętla wątku tła: pobiera początkowy komplet sekretów z KMS,
/// a następnie cyklicznie sprawdza i odnawia te zbliżające się do
/// wygaśnięcia, z exponential backoff przy błędach komunikacji z KMS.
pub async fn run_renewal_loop(cache: Arc<SecretCache>, kms_client: KmsClient, config: AgentConfig) {
    let mut backoff = Duration::from_millis(config.backoff_base_ms);
    let backoff_max = Duration::from_millis(config.backoff_max_ms);

    // Pierwsze, pełne pobranie sekretów przy starcie agenta.
    if let Err(err) = refresh_all(&cache, &kms_client, &config).await {
        tracing::error!(error = %err, "wstępne pobranie sekretów z KMS nie powiodło się");
    }

    // Używamy dynamicznego interwału z konfiguracji
    let mut poll_timer = tokio::time::interval(config.poll_interval());

    loop {
        tokio::select! {
            _ = poll_timer.tick() => {
                // Czyszczenie przeterminowanych sekretów przy każdym cyklu pętli,
                // nawet jeśli żaden sekret nie wymaga odnowienia w KMS.
                cache.purge_expired();

                // Używamy dynamicznego okna wyprzedzenia z konfiguracji
                let expiring = cache.keys_expiring_within(config.renewal_lookahead());
                if expiring.is_empty() {
                    continue;
                }

                tracing::debug!(count = expiring.len(), "odnawiam sekrety zbliżające się do wygaśnięcia");

                match refresh_all(&cache, &kms_client, &config).await {
                    Ok(()) => {
                        backoff = Duration::from_millis(config.backoff_base_ms);
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            backoff_ms = backoff.as_millis(),
                            "odnowienie sekretów nie powiodło się, ponawiam z backoff"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, backoff_max);
                    }
                }
            }
        }
    }
}

/// Pobiera pełny zestaw sekretów z KMS i wstawia je do współdzielonego cache.
async fn refresh_all(
    cache: &Arc<SecretCache>,
    kms_client: &KmsClient,
    config: &AgentConfig,
) -> Result<(), crate::kms::KmsError> {
    let secrets = kms_client.fetch_secrets().await?;

    // Czyszczenie starych / wygasłych sekretów przed załadowaniem nowego zestawu
    cache.purge_expired();

    for secret in secrets {
        let ttl = secret
            .ttl_secs
            .map(Duration::from_secs)
            .unwrap_or_else(|| config.default_ttl());

        cache.insert(secret.key, SecretString::from(secret.value), ttl);
    }

    Ok(())
}