#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ServiceManifest {
    pub service: ServiceInfo,
    pub credentials: Vec<CredentialSpec>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ServiceInfo {
    pub name: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CredentialSpec {
    pub name: String,
    pub r#type: String,
    pub resource: String,
}
