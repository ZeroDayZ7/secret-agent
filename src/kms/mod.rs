use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, error, info, instrument, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::AgentConfig;

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

#[derive(Debug, Clone)]
pub struct SecretPayload {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct IssueCredentialsRequest<'a> {
    pub target_service: &'a str,
    pub target_type: &'a str,
    pub resource: &'a str,
    pub ttl_seconds: u64,
}

/// DTO do odebrania odpowiedzi JSON z KMS
#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KmsSecretsResponse {
    #[zeroize(skip)]
    pub credential_id: uuid::Uuid,
    pub username: String,
    pub password: Zeroizing<String>,
    #[zeroize(skip)]
    pub expires_at: String, // Zachowano ISO8601 String z KMS
}

/// Binarna struktura przesyłana przez UDS IPC w MessagePacku
#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
#[allow(dead_code)]
pub struct UdsSecretPayload {
    pub username: String,
    pub password: Zeroizing<Vec<u8>>,
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
    hmac_key: Zeroizing<Vec<u8>>,
}

impl KmsClient {
    pub fn new(config: &AgentConfig) -> Result<Self, KmsError> {
        info!(
            "Inicjalizacja KmsClient dla client_id: {}",
            config.client_id
        );

        let http = reqwest::Client::builder()
            .timeout(config.kms_timeout())
            .build()?;

        let path = if config.kms_secrets_path.starts_with('/') {
            config.kms_secrets_path.clone()
        } else {
            format!("/{}", config.kms_secrets_path)
        };

        debug!("Skonfigurowano ścieżkę KMS: {}", path);

        Ok(Self {
            http,
            secrets_url: config.secrets_full_url(),
            secrets_path: path,
            client_id: config.client_id.clone(),
            target_service: config.target_service.clone(),
            target_type: config.target_type.clone(),
            resource: config.resource.clone(),
            default_ttl_secs: config.default_ttl_secs,
            hmac_key: config.get_hmac_key().map_err(|e| {
                error!("Błąd podczas pobierania klucza HMAC: {}", e);
                KmsError::Hmac(e)
            })?,
        })
    }

    fn compute_hmac(&self, data: &[u8]) -> Result<String, KmsError> {
        debug!(
            "Obliczanie podpisu HMAC dla danych o długości: {} bajtów",
            data.len()
        );
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).map_err(|e| {
            error!("Nie udało się zainicjalizować HMAC z klucza: {}", e);
            KmsError::Hmac(e.to_string())
        })?;
        mac.update(data);
        let result = mac.finalize();
        let hex_signature = hex::encode(result.into_bytes());
        debug!("Pomyślnie wygenerowano podpis HMAC");
        Ok(hex_signature)
    }

    #[instrument(skip(self), fields(client_id = %self.client_id, target_service = %self.target_service, resource = %self.resource))]
    pub async fn fetch_secrets(&self) -> Result<Vec<SecretPayload>, KmsError> {
        info!("Rozpoczynanie pobierania sekretów z KMS");

        let request_body = IssueCredentialsRequest {
            target_service: &self.target_service,
            target_type: &self.target_type,
            resource: &self.resource,
            ttl_seconds: self.default_ttl_secs,
        };

        let timestamp = chrono::Utc::now().timestamp().to_string();
        let method = "POST";
        let canonical_payload = format!("{}:{}:{}", method, self.secrets_path, timestamp);

        debug!(
            "Kanoniczny ładunek do podpisu HMAC: '{}'",
            canonical_payload
        );

        let signature = self.compute_hmac(canonical_payload.as_bytes())?;

        debug!("Wysyłanie żądania POST do KMS URL: {}", self.secrets_url);
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
            .await
            .map_err(|e| {
                error!("Błąd komunikacji HTTP z serwerem KMS: {}", e);
                e
            })?;

        let status = response.status();
        debug!("Otrzymano odpowiedź z KMS ze statusem HTTP: {}", status);

        if !status.is_success() {
            warn!("KMS zwrócił niepomyślny status HTTP: {}", status);
            return Err(KmsError::UnexpectedStatus(status));
        }

        let mut parsed: KmsSecretsResponse = response.json().await.map_err(|e| {
            error!("Nie udało się zdeserializować odpowiedzi JSON z KMS: {}", e);
            e
        })?;

        debug!(
            "Pomyślnie odebrano i zdeserializowano sekrety z KMS. Credential ID: {}",
            parsed.credential_id
        );

        // Pobieranie własności do zmiennych
        let username = std::mem::take(&mut parsed.username);
        let password_bytes = parsed.password.as_bytes().to_vec();

        debug!(
            "Przygotowywanie pakietu MessagePack (username: '{}', password_len: {} B)",
            username,
            password_bytes.len()
        );

        // Ręczne zbudowanie formatu MessagePack gwarantujące mapę i typ binarny
        let payload = rmpv::Value::Map(vec![
            (
                rmpv::Value::String("username".into()),
                rmpv::Value::String(username.into()),
            ),
            (
                rmpv::Value::String("password".into()),
                rmpv::Value::Binary(password_bytes), // Wymusza format 'bin' kompatybilny z []byte w Go
            ),
        ]);

        // Gotowy ładunek zabezpieczony przed zrzutem pamięci
        let raw_creds_payload = Zeroizing::new(rmp_serde::to_vec(&payload).map_err(|e| {
            error!("Błąd kodowania MessagePack rmpv::Value: {}", e);
            e
        })?);

        info!(
            "Pomyślnie zaszyfrowano i przygotowano ładunek sekretu dla klucza: {}_{}",
            self.target_service, self.resource
        );

        Ok(vec![SecretPayload {
            key: format!("{}_{}", self.target_service, self.resource),
            value: raw_creds_payload,
            ttl_secs: Some(self.default_ttl_secs),
        }])
    }
}
