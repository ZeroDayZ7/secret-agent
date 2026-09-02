use std::collections::HashMap;
use std::time::Instant;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::AgentConfig;
use crate::manifest::CredentialSpec;

type HmacSha256 = Hmac<Sha256>;

#[derive(thiserror::Error, Debug)]
pub enum KmsError {
    #[error("Błąd obliczania HMAC: {0}")]
    Hmac(String),
    #[error("Błąd żądania HTTP do KMS: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Błąd kodowania MessagePack dla ramki UDS: {0}")]
    MsgpackEncode(#[from] rmp_serde::encode::Error),
    #[error("KMS zwrócił nieoczekiwany status HTTP: {0}")]
    UnexpectedStatus(reqwest::StatusCode),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SecretPayload {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub ttl_secs: Option<u64>,
    pub expires_at: Option<Instant>,
}

impl SecretPayload {
    pub fn is_valid(&self) -> bool {
        self.expires_at
            .map(|expires_at| expires_at > Instant::now())
            .unwrap_or(true)
    }
}

#[derive(Debug, Serialize)]
struct IssueCredentialsRequest<'a> {
    pub name: &'a str,
    pub credential_type: &'a str,
    pub resource: &'a str,
    pub ttl_seconds: u64,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct BatchCredentialRequest {
    pub credentials: Vec<CredentialSpec>,
    pub ttl_seconds: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct BatchCredentialResponse {
    pub credentials: HashMap<String, rmpv::Value>,
}

#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KmsSecretsResponse {
    #[zeroize(skip)]
    pub credential_id: uuid::Uuid,
    pub username: String,
    pub password: Zeroizing<String>,
    #[zeroize(skip)]
    pub expires_at: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UdsSecretPayload {
    pub username: String,
    pub password: Zeroizing<Vec<u8>>,
}

pub struct KmsClient {
    http: reqwest::Client,
    secrets_url: String,
    secrets_path: String,
    client_id: String,
    default_ttl_secs: u64,
    hmac_key: Zeroizing<Vec<u8>>,
}

impl KmsClient {
    pub fn new(config: &AgentConfig) -> Result<Self, KmsError> {
        tracing::info!(
            client_id = %config.client_id,
            "Inicjalizacja KmsClient"
        );

        let http = reqwest::Client::builder()
            .timeout(config.kms_timeout())
            .build()?;

        let path = if config.kms_secrets_path.starts_with('/') {
            config.kms_secrets_path.clone()
        } else {
            format!("/{}", config.kms_secrets_path)
        };

        tracing::debug!(kms_path = %path, "Skonfigurowano ścieżkę KMS");

        Ok(Self {
            http,
            secrets_url: config.secrets_full_url(),
            secrets_path: path,
            client_id: config.client_id.clone(),
            default_ttl_secs: config.default_ttl_secs,
            hmac_key: config.get_hmac_key().map_err(|e| {
                tracing::error!(error = %e, "Błąd podczas pobierania klucza HMAC");
                KmsError::Hmac(e)
            })?,
        })
    }

    fn compute_hmac(&self, data: &[u8]) -> Result<String, KmsError> {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).map_err(|e| {
            tracing::error!(error = %e, "Nie udało się zainicjalizować HMAC z klucza");
            KmsError::Hmac(e.to_string())
        })?;
        mac.update(data);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    pub async fn fetch_single_secret(
        &self,
        credential: &CredentialSpec,
    ) -> Result<SecretPayload, KmsError> {
        let request_body = IssueCredentialsRequest {
            name: &credential.name,
            credential_type: &credential.r#type,
            resource: &credential.resource,
            ttl_seconds: self.default_ttl_secs,
        };

        let timestamp = chrono::Utc::now().timestamp().to_string();
        let canonical_payload = format!("POST:{}:{}", self.secrets_path, timestamp);
        let signature = self.compute_hmac(canonical_payload.as_bytes())?;

        let response = self
            .http
            .post(&self.secrets_url)
            .header("X-Signature", signature)
            .header("X-Service-ID", &self.client_id)
            .header("X-Service-Name", &self.client_id)
            .header("X-Timestamp", timestamp)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                credential = %credential.name,
                "KMS zwrócił status niepowodzenia"
            );
            return Err(KmsError::UnexpectedStatus(response.status()));
        }

        let parsed: KmsSecretsResponse = response.json().await?;
        let username = parsed.username.clone();
        let password_bytes = parsed.password.as_bytes().to_vec();
        let payload_map = rmpv::Value::Map(vec![
            (
                rmpv::Value::String("username".into()),
                rmpv::Value::String(username.into()),
            ),
            (
                rmpv::Value::String("password".into()),
                rmpv::Value::Binary(password_bytes),
            ),
        ]);
        let value = rmp_serde::to_vec(&payload_map)?;
        let expires_at =
            Some(Instant::now() + std::time::Duration::from_secs(self.default_ttl_secs));

        Ok(SecretPayload {
            key: credential.name.clone(),
            value: Zeroizing::new(value),
            ttl_secs: Some(self.default_ttl_secs),
            expires_at,
        })
    }

    #[allow(dead_code)]
    pub async fn fetch_secrets_for_manifest(
        &self,
        credentials: &[CredentialSpec],
    ) -> Result<Vec<SecretPayload>, KmsError> {
        let mut results = Vec::with_capacity(credentials.len());
        for credential in credentials {
            results.push(self.fetch_single_secret(credential).await?);
        }
        Ok(results)
    }

    #[allow(dead_code)]
    pub async fn fetch_batch(
        &self,
        credentials: &[CredentialSpec],
    ) -> Result<HashMap<String, SecretPayload>, KmsError> {
        let mut result = HashMap::new();
        for credential in credentials {
            let secret = self.fetch_single_secret(credential).await?;
            result.insert(secret.key.clone(), secret);
        }
        Ok(result)
    }
}
