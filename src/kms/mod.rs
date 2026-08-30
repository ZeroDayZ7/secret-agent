use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::AgentConfig;

type HmacSha256 = Hmac<Sha256>;

#[derive(thiserror::Error, Debug)]
pub enum KmsError {
    #[error("Błąd obliczania HMAC: {0}")]
    Hmac(String),
    #[error("Błąd żądania HTTP do KMS: {0}")]
    Http(#[from] reqwest::Error),
    #[error("KMS zwrócił nieoczekiwany status HTTP: {0}")]
    UnexpectedStatus(reqwest::StatusCode),
}

#[derive(Debug, Clone)]
pub struct SecretPayload {
    pub key: String,
    pub value: SecretString,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct IssueCredentialsRequest<'a> {
    pub target_service: &'a str,
    pub target_type: &'a str,
    pub resource: &'a str,
    pub ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct KmsSecretsResponse {
    #[allow(dead_code)]
    pub credential_id: uuid::Uuid,
    pub username: String,
    pub password: SecretString,
    #[allow(dead_code)]
    pub expires_at: String,
}

pub struct KmsClient {
    http: reqwest::Client,
    secrets_url: String,
    secrets_path: String,
    client_id: String,
    target_service: String,
    target_type: String,
    resource: String,
    default_ttl_secs: u64,
    hmac_key: SecretString,
}

impl KmsClient {
    pub fn new(config: &AgentConfig) -> Result<Self, KmsError> {
        let http = reqwest::Client::builder()
            .timeout(config.kms_timeout())
            .build()?;

        let path = if config.kms_secrets_path.starts_with('/') {
            config.kms_secrets_path.clone()
        } else {
            format!("/{}", config.kms_secrets_path)
        };

        Ok(Self {
            http,
            secrets_url: config.secrets_full_url(),
            secrets_path: path,
            client_id: config.client_id.clone(),
            target_service: config.target_service.clone(),
            target_type: config.target_type.clone(),
            resource: config.resource.clone(),
            default_ttl_secs: config.default_ttl_secs,
            hmac_key: SecretString::from(config.hmac_key.clone()),
        })
    }

    fn compute_hmac(&self, data: &[u8]) -> Result<String, KmsError> {
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.expose_secret().as_bytes())
            .map_err(|e| KmsError::Hmac(e.to_string()))?;
        mac.update(data);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    pub async fn fetch_secrets(&self) -> Result<Vec<SecretPayload>, KmsError> {
        let request_body = IssueCredentialsRequest {
            target_service: &self.target_service,
            target_type: &self.target_type,
            resource: &self.resource,
            ttl_seconds: self.default_ttl_secs,
        };

        let timestamp = chrono::Utc::now().timestamp().to_string();
        let method = "POST";
        let canonical_payload = format!("{}:{}:{}", method, self.secrets_path, timestamp);

        let signature = self.compute_hmac(canonical_payload.as_bytes())?;

        let response = self
            .http
            .post(&self.secrets_url)
            .header("X-Signature", signature)
            .header("X-Service-ID", &self.client_id)
            .header("X-Service-Name", &self.client_id)
            .header("X-Timestamp", timestamp)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(KmsError::UnexpectedStatus(response.status()));
        }

        let parsed: KmsSecretsResponse = response.json().await?;

        // Formatujemy wynik jako ustrukturyzowany pakiet JSON dla Postgresa
        let pg_json = serde_json::json!({
            "username": parsed.username,
            "password": parsed.password.expose_secret()
        })
        .to_string();

        Ok(vec![SecretPayload {
            key: format!("{}_postgres", self.target_service),
            value: SecretString::from(pg_json),
            ttl_secs: Some(self.default_ttl_secs),
        }])
    }
}
