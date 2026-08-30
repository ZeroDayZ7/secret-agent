use std::sync::Arc;
use std::time::Duration;

use crate::cache::SecretCache;
use crate::config::AgentConfig;
use crate::kms::KmsClient;

pub async fn run_renewal_loop(cache: Arc<SecretCache>, kms_client: KmsClient, config: AgentConfig) {
    let mut backoff = Duration::from_millis(config.backoff_base_ms);
    let backoff_max = Duration::from_millis(config.backoff_max_ms);

    tracing::info!("📥 Pobieram początkowy zestaw poświadczeń z KMS...");
    if let Err(err) = refresh_all(&cache, &kms_client, &config).await {
        tracing::error!(error = %err, "❌ Wstępne pobranie sekretów z KMS nie powiodło się");
    } else {
        tracing::info!("✅ Początkowe poświadczenia zostały pomyślnie załadowane do cache agenta");
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

                match refresh_all(&cache, &kms_client, &config).await {
                    Ok(()) => {
                        tracing::info!("✅ Pomyślnie odnowiono poświadczenia z KMS");
                        backoff = Duration::from_millis(config.backoff_base_ms);
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            backoff_ms = backoff.as_millis(),
                            "❌ Ponawiam próbę z exponential backoff"
                        );
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
    kms_client: &KmsClient,
    config: &AgentConfig,
) -> Result<(), crate::kms::KmsError> {
    let secrets = kms_client.fetch_secrets().await?;

    cache.purge_expired();

    for secret in secrets {
        let ttl = secret
            .ttl_secs
            .map(Duration::from_secs)
            .unwrap_or_else(|| config.default_ttl());

        cache.insert(secret.key, secret.value, ttl);
    }

    Ok(())
}
