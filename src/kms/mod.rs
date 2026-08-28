use std::path::Path;
use std::time::Duration;

use secrecy::SecretString;
use serde::Deserialize;

use crate::config::AgentConfig;

#[derive(thiserror::Error, Debug)]
pub enum KmsError {
    #[error("nie udało się odczytać tokenu ServiceAccount: {0}")]
    ServiceAccountTokenRead(#[from] std::io::Error),
    #[error("błąd żądania HTTP do KMS: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KMS zwrócił nieoczekiwany status: {0}")]
    UnexpectedStatus(reqwest::StatusCode),
}

#[derive(Debug, Deserialize)]
pub struct SecretPayload {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct KmsSecretsResponse {
    secrets: Vec<SecretPayload>,
}

/// Async klient HTTP do centralnego serwera KMS, autoryzujący się
/// tokenem ServiceAccount montowanym przez Kubernetes (projected token).
pub struct KmsClient {
    http: reqwest::Client,
    base_url: String,
    sa_token_path: std::path::PathBuf,
    client_id: String,
}

impl KmsClient {
    pub fn new(config: &AgentConfig) -> Result<Self, KmsError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            http,
            base_url: config.kms_url.clone(),
            sa_token_path: config.sa_token_path.clone(),
            client_id: config.client_id.clone(),
        })
    }

    /// Odczytuje aktualny token ServiceAccount z filesystemu K8s.
    /// Token jest okresowo rotowany przez kubelet, więc czytamy go
    /// przy każdej autoryzacji zamiast cache'ować w pamięci na stałe.
    async fn read_service_account_token(&self) -> Result<SecretString, KmsError> {
        let raw = tokio::fs::read_to_string(&self.sa_token_path).await?;
        Ok(SecretString::from(raw.trim().to_owned()))
    }

    /// Pobiera aktualny zestaw sekretów przypisanych do tego klienta.
    ///
    /// MOCK: docelowo endpoint i format odpowiedzi zależą od kontraktu
    /// własnego serwera KMS — do uzupełnienia zgodnie ze specyfikacją API.
    pub async fn fetch_secrets(&self) -> Result<Vec<SecretPayload>, KmsError> {
        use secrecy::ExposeSecret;

        let sa_token = self.read_service_account_token().await?;
        let url = format!("{}/v1/secrets", self.base_url.trim_end_matches('/'));

        let response = self
            .http
            .get(&url)
            .bearer_auth(sa_token.expose_secret())
            .header("X-Client-Id", &self.client_id)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(KmsError::UnexpectedStatus(response.status()));
        }

        let parsed: KmsSecretsResponse = response.json().await?;
        Ok(parsed.secrets)
    }
}

/// Sprawdza, czy podana ścieżka tokenu istnieje — użyteczne przy starcie
/// agenta do wczesnego wykrycia błędnej konfiguracji montowania woluminu.
pub fn service_account_token_present(path: &Path) -> bool {
    path.exists()
}
