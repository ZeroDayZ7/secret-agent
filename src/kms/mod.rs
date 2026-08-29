use hmac::{Hmac, Mac};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::AgentConfig;

type HmacSha256 = Hmac<Sha256>;

#[derive(thiserror::Error, Debug)]
pub enum KmsError {
    #[error("błąd obliczania HMAC: {0}")]
    Hmac(String),
    #[error("błąd żądania HTTP do KMS: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KMS zwrócił nieoczekiwany status: {0}")]
    UnexpectedStatus(reqwest::StatusCode),
}

#[derive(Debug, Serialize)]
struct IssueCredentialsRequest<'a> {
    pub client_id: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct SecretPayload {
    pub key: String,
    pub value: SecretString,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct KmsSecretsResponse {
    pub secrets: Vec<SecretPayload>,
}

pub struct KmsClient {
    http: reqwest::Client,
    secrets_url: String,
    client_id: String,
    hmac_key: SecretString,
}

impl KmsClient {
    pub fn new(config: &AgentConfig) -> Result<Self, KmsError> {
        let http = reqwest::Client::builder()
            .timeout(config.kms_timeout())
            .build()?;

        Ok(Self {
            http,
            secrets_url: config.secrets_full_url(),
            client_id: config.client_id.clone(),
            hmac_key: SecretString::from(config.hmac_key.clone()),
        })
    }

    /// Oblicza podpis HMAC-SHA256 dla przekazanej treść żądania (payloadu) lub identyfikatora.
    fn compute_hmac(&self, data: &[u8]) -> Result<String, KmsError> {
        use secrecy::ExposeSecret;
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.expose_secret().as_bytes())
            .map_err(|e| KmsError::Hmac(e.to_string()))?;
        mac.update(data);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    pub async fn fetch_secrets(&self) -> Result<Vec<SecretPayload>, KmsError> {
        let request_body = IssueCredentialsRequest {
            client_id: &self.client_id,
        };

        // Serializujemy ciało żądania do JSON, aby użyć go jako bazy do wyliczenia HMAC
        let body_bytes =
            serde_json::to_vec(&request_body).map_err(|e| KmsError::Hmac(e.to_string()))?;

        let signature = self.compute_hmac(&body_bytes)?;

        let response = self
            .http
            .post(&self.secrets_url)
            .header("X-Signature", signature)
            .header("X-Service-ID", &self.client_id)
            .header("X-Service-Name", &self.client_id)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(KmsError::UnexpectedStatus(response.status()));
        }

        let parsed: KmsSecretsResponse = response.json().await?;
        Ok(parsed.secrets)
    }
}
