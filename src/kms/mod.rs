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
#[derive(Clone)]
pub struct SecretPayload {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub ttl_secs: Option<u64>,
    pub expires_at: Option<Instant>,
}

impl std::fmt::Debug for SecretPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPayload")
            .field("key", &self.key)
            .field("value", &"<REDACTED>")
            .field("ttl_secs", &self.ttl_secs)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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
    pub target_service: &'a str,
    pub target_type: &'a str,
    pub resource: &'a str,
    pub ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct BatchCredentialRequest<'a> {
    pub credentials: &'a [CredentialSpec],
    pub ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct BatchCredentialResponse {
    pub credentials: HashMap<String, KmsSecretsResponse>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KmsSecretsResponse {
    #[zeroize(skip)]
    pub credential_id: uuid::Uuid,
    pub username: String,
    pub password: Zeroizing<String>,
    #[zeroize(skip)]
    pub expires_at: String,
}

impl std::fmt::Debug for KmsSecretsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsSecretsResponse")
            .field("credential_id", &self.credential_id)
            .field("username", &self.username)
            .field("password", &"<REDACTED>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[allow(dead_code)]
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct UdsSecretPayload {
    pub username: String,
    pub password: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for UdsSecretPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdsSecretPayload")
            .field("username", &self.username)
            .field("password", &"<REDACTED>")
            .finish()
    }
}

pub struct KmsClient {
    http: reqwest::Client,
    secrets_url: String,
    secrets_path: String,
    batch_secrets_url: String,
    batch_secrets_path: String,
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

        let batch_path = if config.kms_batch_secrets_path.starts_with('/') {
            config.kms_batch_secrets_path.clone()
        } else {
            format!("/{}", config.kms_batch_secrets_path)
        };

        tracing::debug!(
            kms_path = %path,
            kms_batch_path = %batch_path,
            "Skonfigurowano ścieżki KMS"
        );

        Ok(Self {
            http,
            secrets_url: config.kms_full_url(&path),
            secrets_path: path,
            batch_secrets_url: config.kms_full_url(&batch_path),
            batch_secrets_path: batch_path,
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
        let request_id = uuid::Uuid::new_v4().to_string();
        let started_at = std::time::Instant::now();

        let target_service = credential.resolved_target_service();
        let request_body = IssueCredentialsRequest {
            name: &credential.name,
            target_service: target_service.as_str(),
            target_type: &credential.r#type,
            resource: &credential.resource,
            ttl_seconds: self.default_ttl_secs,
        };

        let timestamp = chrono::Utc::now().timestamp().to_string();
        let canonical_payload = format!("POST:{}:{}", self.secrets_path, timestamp);
        let signature = self.compute_hmac(canonical_payload.as_bytes())?;

        let body_json = serde_json::to_string_pretty(&request_body).unwrap_or_default();

        tracing::debug!(
            "[AGENT 1.1] Budowanie żądania pojedynczego credentialu do KMS\n\
             ├─ request_id:   {}\n\
             ├─ url:          {}\n\
             ├─ credential:   {}\n\
             ├─ target_service: {}\n\
             ├─ target_type:  {}\n\
             ├─ resource:     {}\n\
             ├─ x-service-id: {}\n\
             ├─ x-timestamp:  {}\n\
             ├─ x-signature:  {}\n\
             └─ payload:\n{}",
            request_id,
            self.secrets_url,
            credential.name,
            target_service,
            credential.r#type,
            credential.resource,
            self.client_id,
            timestamp,
            signature,
            body_json
        );

        tracing::info!(
            request_id = %request_id,
            credential = %credential.name,
            target_service = %target_service,
            target_type = %credential.r#type,
            resource = %credential.resource,
            action = "issue-single",
            "[AGENT 1.2] Wysyłam żądanie pojedynczego credentialu do KMS"
        );

        let response = self
            .http
            .post(&self.secrets_url)
            .header("X-Request-ID", &request_id)
            .header("X-Signature", &signature)
            .header("X-Service-ID", &self.client_id)
            .header("X-Service-Name", &self.client_id)
            .header("X-Timestamp", &timestamp)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let latency_ms = started_at.elapsed().as_millis();
        tracing::info!(
            request_id = %request_id,
            credential = %credential.name,
            status = response.status().as_u16(),
            latency_ms = latency_ms,
            "📥 Otrzymano odpowiedź z KMS"
        );

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

    pub async fn fetch_batch_bootstrap(
        &self,
        credentials: &[CredentialSpec],
    ) -> Result<HashMap<String, SecretPayload>, KmsError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let started_at = std::time::Instant::now();

        let request_body = BatchCredentialRequest {
            credentials,
            ttl_seconds: self.default_ttl_secs,
        };

        let timestamp = chrono::Utc::now().timestamp().to_string();
        let canonical_payload = format!("POST:{}:{}", self.batch_secrets_path, timestamp);
        let signature = self.compute_hmac(canonical_payload.as_bytes())?;

        let body_json = serde_json::to_string_pretty(&request_body).unwrap_or_default();

        tracing::debug!(
            "[AGENT 2.1] Budowanie żądania batch bootstrap do KMS\n\
             ├─ request_id:   {}\n\
             ├─ url:          {}\n\
             ├─ count:        {}\n\
             ├─ x-service-id: {}\n\
             ├─ x-timestamp:  {}\n\
             ├─ x-signature:  {}\n\
             └─ payload:\n{}",
            request_id,
            self.batch_secrets_url,
            credentials.len(),
            self.client_id,
            timestamp,
            signature,
            body_json
        );

        tracing::info!(
            request_id = %request_id,
            items_count = credentials.len(),
            action = "issue-batch",
            "[AGENT 2.2] Wysyłam batch bootstrap do KMS"
        );

        let response = self
            .http
            .post(&self.batch_secrets_url)
            .header("X-Request-ID", &request_id)
            .header("X-Signature", &signature)
            .header("X-Service-ID", &self.client_id)
            .header("X-Service-Name", &self.client_id)
            .header("X-Timestamp", &timestamp)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let latency_ms = started_at.elapsed().as_millis();
        tracing::info!(
            request_id = %request_id,
            status = response.status().as_u16(),
            latency_ms = latency_ms,
            "📥 Otrzymano odpowiedź z KMS (Batch)"
        );

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "KMS zwrócił status niepowodzenia dla żądania batch"
            );
            return Err(KmsError::UnexpectedStatus(response.status()));
        }

        let parsed: BatchCredentialResponse = response.json().await?;
        let expires_at =
            Some(Instant::now() + std::time::Duration::from_secs(self.default_ttl_secs));
        let mut map = HashMap::new();

        for (key, secret_resp) in parsed.credentials {
            let payload_map = rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("username".into()),
                    rmpv::Value::String(secret_resp.username.clone().into()),
                ),
                (
                    rmpv::Value::String("password".into()),
                    rmpv::Value::Binary(secret_resp.password.as_bytes().to_vec()),
                ),
            ]);
            let value = rmp_serde::to_vec(&payload_map)?;

            map.insert(
                key.clone(),
                SecretPayload {
                    key,
                    value: Zeroizing::new(value),
                    ttl_secs: Some(self.default_ttl_secs),
                    expires_at,
                },
            );
        }

        Ok(map)
    }
}
