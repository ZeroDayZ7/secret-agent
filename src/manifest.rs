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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_service: Option<String>,
    pub r#type: String,
    pub resource: String,
}

impl CredentialSpec {
    pub fn resolved_target_service(&self) -> String {
        self.target_service
            .clone()
            .unwrap_or_else(|| self.resource.clone())
    }
}
