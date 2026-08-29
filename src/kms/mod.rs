use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

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
            secrets_url: config.secrets_full_url(),
            sa_token_path: config.sa_token_path.clone(),
            client_id: config.client_id.clone(),
        })
    }

    async fn read_service_account_token(&self) -> Result<SecretString, KmsError> {
        let raw = tokio::fs::read_to_string(&self.sa_token_path).await?;
        Ok(SecretString::from(raw.trim().to_owned()))
    }

    pub async fn fetch_secrets(&self) -> Result<Vec<SecretPayload>, KmsError> {
        let sa_token = self.read_service_account_token().await?;

        let request_body = IssueCredentialsRequest {
            client_id: &self.client_id,
        };

        // Wykonujemy żądanie POST pod /api/v1/agent/credentials/issue
        let response = self
            .http
            .post(&self.secrets_url)
            .bearer_auth(sa_token.expose_secret())
            .header("X-Client-Id", &self.client_id)
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
