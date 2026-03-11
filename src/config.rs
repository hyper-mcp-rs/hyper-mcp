use crate::{cli::Cli, naming::PluginName};
use anyhow::{Context, Result};
use bytesize::ByteSize;
use camino::Utf8PathBuf;
use dashmap::DashMap;
use regex::RegexSet;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize, de};
use serde_with::{DisplayFromStr, serde_as};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};
use url::Url;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Basic { username: String, password: String },
    Token { token: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum InternalAuthConfig {
    Basic { username: String, password: String },
    Keyring(KeyringEntryId),
    Token { token: String },
}

impl<'de> Deserialize<'de> for AuthConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let internal = InternalAuthConfig::deserialize(deserializer)?;
        match internal {
            InternalAuthConfig::Basic { username, password } => {
                Ok(AuthConfig::Basic { username, password })
            }
            InternalAuthConfig::Token { token } => Ok(AuthConfig::Token { token }),
            InternalAuthConfig::Keyring(id) => {
                use keyring::Entry;
                use serde::de;

                let entry: Entry = (id).try_into().map_err(de::Error::custom)?;
                let secret = entry.get_secret().map_err(de::Error::custom)?;
                Ok(serde_json::from_slice::<AuthConfig>(secret.as_slice())
                    .map_err(de::Error::custom)?)
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auths: Option<HashMap<Url, AuthConfig>>,

    #[serde(default)]
    pub dynamic_loading: bool,

    #[serde(default)]
    pub oci: OciConfig,

    pub plugins: DashMap<PluginName, PluginConfig>,
}

impl Config {
    pub async fn load(cli: &Cli) -> Result<Config> {
        // Get default config path in the user's config directory
        let default_config_path = dirs::config_dir()
            .map(|mut path| {
                path.push("hyper-mcp");
                path.push("config.json");
                path
            })
            .unwrap();

        let config_path = cli.config_file.as_ref().unwrap_or(&default_config_path);
        if !config_path.exists() {
            return Err(anyhow::anyhow!(
                "Config file not found at: {}. Please create a config file first.",
                config_path.display()
            ));
        }
        tracing::info!("Using config file at {}", config_path.display());
        let ext = config_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let content = tokio::fs::read_to_string(config_path)
            .await
            .with_context(|| format!("Failed to read config file at {}", config_path.display()))?;

        let mut config: Config = match ext {
            "json" => serde_json::from_str(&content)?,
            "yaml" | "yml" => serde_yaml::from_str(&content)?,
            "toml" => toml::from_str(&content)?,
            _ => return Err(anyhow::anyhow!("Unsupported config format: {ext}")),
        };

        let mut oci = config.oci.clone();

        if let Some(skip) = cli.insecure_skip_signature {
            oci.insecure_skip_signature = skip;
        }
        if let Some(use_tuf) = cli.use_sigstore_tuf_data {
            oci.use_sigstore_tuf_data = use_tuf;
        }
        if let Some(rekor_keys) = &cli.rekor_pub_keys {
            oci.rekor_pub_keys = Some(rekor_keys.clone());
        }
        if let Some(fulcio_certs) = &cli.fulcio_certs {
            oci.fulcio_certs = Some(fulcio_certs.clone());
        }
        if let Some(issuer) = &cli.cert_issuer {
            oci.cert_issuer = Some(issuer.clone());
        }
        if let Some(email) = &cli.cert_email {
            oci.cert_email = Some(email.clone());
        }
        if let Some(url) = &cli.cert_url {
            oci.cert_url = Some(url.clone());
        }
        config.oci = oci;

        if let Some(dynamic_loading) = &cli.dynamic_loading {
            config.dynamic_loading = *dynamic_loading;
        }

        Ok(config)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OciConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_issuer: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulcio_certs: Option<PathBuf>,

    pub insecure_skip_signature: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekor_pub_keys: Option<PathBuf>,

    pub use_sigstore_tuf_data: bool,
}

impl Default for OciConfig {
    fn default() -> Self {
        OciConfig {
            cert_email: None,
            cert_issuer: None,
            cert_url: None,
            fulcio_certs: None,
            insecure_skip_signature: false,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginConfig {
    #[serde(rename = "url", alias = "path")]
    pub url: Url,
    pub runtime_config: Option<RuntimeConfig>,
}

impl JsonSchema for PluginConfig {
    fn schema_name() -> Cow<'static, str> {
        "PluginConfig".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::PluginConfig").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri",
                    "description": "The URL or path of the plugin"
                },
                "runtime_config": generator.subschema_for::<Option<RuntimeConfig>>()
            },
            "required": ["url"]
        })
    }
}

mod skip_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(set: &Option<RegexSet>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match set {
            Some(set) => serializer.serialize_some(set.patterns()),
            None => serializer.serialize_none(),
        }
    }

    fn anchor_pattern(pattern: &String) -> String {
        // Anchor the pattern to match the entire string
        // only if it is not already anchored
        if pattern.starts_with("^")
            || pattern.starts_with("\\A")
            || pattern.ends_with("$")
            || pattern.ends_with("\\z")
        {
            pattern.clone()
        } else {
            format!("^{}$", pattern)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<RegexSet>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let patterns: Option<Vec<String>> = Option::deserialize(deserializer)?;
        match patterns {
            Some(patterns) => RegexSet::new(
                patterns
                    .into_iter()
                    .map(|p| anchor_pattern(&p))
                    .collect::<Vec<_>>(),
            )
            .map(Some)
            .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AllowedPath {
    pub host: Utf8PathBuf,
    pub plugin: Utf8PathBuf,
}

impl JsonSchema for AllowedPath {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "AllowedPath".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AllowedPath").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "A path mapping in the format 'host_path' or 'host_path:plugin_path' (';' separator on Windows)"
        })
    }
}

impl<'de> Deserialize<'de> for AllowedPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut path_iter = s
            .splitn(2, if cfg!(windows) { ";" } else { ":" })
            .map(str::trim);
        match path_iter.next() {
            Some(host) => {
                if !Utf8PathBuf::from(host).exists() {
                    return Err(de::Error::custom(format!(
                        "host path {} does not exist",
                        host
                    )));
                }
                Ok(AllowedPath {
                    host: Utf8PathBuf::from(host),
                    plugin: Utf8PathBuf::from(
                        path_iter.next().filter(|p| !p.is_empty()).unwrap_or(host),
                    ),
                })
            }
            None => Err(de::Error::custom("Missing host path")),
        }
    }
}

impl Serialize for AllowedPath {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.plugin == self.host {
            serializer.serialize_str(self.host.as_str())
        } else {
            serializer.serialize_str(&format!(
                "{}{}{}",
                self.host,
                if cfg!(windows) { ";" } else { ":" },
                self.plugin
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[schemars(description = "Identifies a keyring entry for secure credential storage.")]
pub struct KeyringEntryId {
    #[schemars(
        description = "The keyring service name that the credential is stored under (e.g. \"my-app\")."
    )]
    pub service: String,
    #[schemars(description = "The username associated with the keyring entry (e.g. \"admin\").")]
    pub user: String,
}

impl TryFrom<KeyringEntryId> for keyring::Entry {
    type Error = keyring::Error;

    fn try_from(id: KeyringEntryId) -> Result<Self, Self::Error> {
        keyring::Entry::new(&id.service, &id.user)
    }
}

impl TryFrom<&KeyringEntryId> for keyring::Entry {
    type Error = keyring::Error;

    fn try_from(id: &KeyringEntryId) -> Result<Self, Self::Error> {
        keyring::Entry::new(&id.service, &id.user)
    }
}

#[serde_as]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeConfig {
    // List of prompts to skip loading at runtime.
    #[serde(with = "skip_serde", default)]
    pub skip_prompts: Option<RegexSet>,
    // List of resource templatess to skip loading at runtime.
    #[serde(with = "skip_serde", default)]
    pub skip_resource_templates: Option<RegexSet>,
    // List of resources to skip loading at runtime.
    #[serde(with = "skip_serde", default)]
    pub skip_resources: Option<RegexSet>,
    // List of tools to skip loading at runtime.
    #[serde(with = "skip_serde", default)]
    pub skip_tools: Option<RegexSet>,
    pub allowed_hosts: Option<Vec<String>>,
    pub allowed_paths: Option<Vec<AllowedPath>>,
    pub allowed_secrets: Option<Vec<KeyringEntryId>>,
    pub env_vars: Option<HashMap<String, String>>,

    #[serde_as(as = "Option<DisplayFromStr>")]
    pub memory_limit: Option<ByteSize>,
}

impl JsonSchema for RuntimeConfig {
    fn schema_name() -> Cow<'static, str> {
        "RuntimeConfig".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::RuntimeConfig").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "description": "Plugin-specific runtime configuration that controls sandboxing, filtering, and resource limits.",
            "properties": {
                "skip_prompts": {
                    "anyOf": [
                        { "type": "array", "items": { "type": "string" } },
                        { "type": "null" }
                    ],
                    "description": "List of regex patterns for prompt names to skip. Patterns are automatically anchored with ^ and $."
                },
                "skip_resource_templates": {
                    "anyOf": [
                        { "type": "array", "items": { "type": "string" } },
                        { "type": "null" }
                    ],
                    "description": "List of regex patterns for resource template names to skip. Patterns are automatically anchored with ^ and $."
                },
                "skip_resources": {
                    "anyOf": [
                        { "type": "array", "items": { "type": "string" } },
                        { "type": "null" }
                    ],
                    "description": "List of regex patterns for resource names to skip. Patterns are automatically anchored with ^ and $."
                },
                "skip_tools": {
                    "anyOf": [
                        { "type": "array", "items": { "type": "string" } },
                        { "type": "null" }
                    ],
                    "description": "List of regex patterns for tool names to skip. Patterns are automatically anchored with ^ and $."
                },
                "allowed_hosts": {
                    "description": "List of hostnames or IP addresses the plugin is allowed to connect to.",
                    "allOf": [generator.subschema_for::<Option<Vec<String>>>()]
                },
                "allowed_paths": {
                    "description": "List of file system paths the plugin is allowed to access.",
                    "allOf": [generator.subschema_for::<Option<Vec<AllowedPath>>>()]
                },
                "allowed_secrets": {
                    "description": "List of keyring entries the plugin is allowed to read..",
                    "allOf": [generator.subschema_for::<Option<Vec<KeyringEntryId>>>()]
                },
                "env_vars": {
                    "description": "Key-value pairs of environment variables to inject into the plugin runtime.",
                    "allOf": [generator.subschema_for::<Option<HashMap<String, String>>>()]
                },
                "memory_limit": {
                    "anyOf": [
                        { "type": "string" },
                        { "type": "null" }
                    ],
                    "description": "Memory limit for the plugin as a human-readable string (e.g. '256MB', '1GB', '512Mi')."
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;
    use tokio::runtime::Runtime;

    #[test]
    fn test_load_valid_yaml_config() {
        use std::io::Write;

        let rt = Runtime::new().unwrap();

        // Create temp directories so allowed_paths host validation passes
        let base = TempDir::new().unwrap();
        let b = base.path();
        for d in &["tmp", "var/log", "home/user/data"] {
            std::fs::create_dir_all(b.join(d)).unwrap();
        }
        let p = |s: &str| -> String { b.join(s).to_str().unwrap().to_string() };

        // Generate the fixture YAML dynamically with real paths
        let yaml_content = format!(
            r#"plugins:
  test_plugin:
    url: "file:///path/to/plugin"
    runtime_config:
      skip_tools:
        - "tool1"
        - "tool2"
      allowed_hosts:
        - "example.com"
        - "localhost"
      allowed_paths:
        - "{tmp}"
        - "{var_log}:/plugin/logs"
        - "{home_user_data}"
      env_vars:
        DEBUG: "true"
        LOG_LEVEL: "info"
      memory_limit: "1GB"

  another_plugin:
    url: "https://example.com/plugin"
    runtime_config:
      allowed_hosts:
        - "api.example.com"

  minimal_plugin:
    url: "http://localhost:3000/plugin"
"#,
            tmp = p("tmp"),
            var_log = p("var/log"),
            home_user_data = p("home/user/data"),
        );

        let mut tmp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        tmp_file.write_all(yaml_content.as_bytes()).unwrap();
        tmp_file.flush().unwrap();

        let cli = Cli {
            config_file: Some(tmp_file.path().to_path_buf()),
            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Failed to load valid YAML config: {:?}",
            config_result.err()
        );

        let config = config_result.unwrap();
        assert_eq!(config.plugins.len(), 3, "Expected 3 plugins in the config");

        // Verify plugin names (DashMap doesn't guarantee order, so check contains_key)
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("test_plugin").unwrap())
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("another_plugin").unwrap())
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("minimal_plugin").unwrap())
        );

        // Verify plugin configs
        let test_plugin = config
            .plugins
            .get(&PluginName::try_from("test_plugin").unwrap())
            .unwrap();
        assert_eq!(test_plugin.url.to_string(), "file:///path/to/plugin");

        let runtime_config = test_plugin.runtime_config.as_ref().unwrap();
        assert_eq!(runtime_config.skip_tools.as_ref().unwrap().len(), 2);
        assert_eq!(runtime_config.allowed_hosts.as_ref().unwrap().len(), 2);
        assert_eq!(runtime_config.allowed_paths.as_ref().unwrap().len(), 3);

        // Verify allowed_paths structure
        let allowed_paths = runtime_config.allowed_paths.as_ref().unwrap();
        assert_eq!(allowed_paths[0].host.as_str(), p("tmp"));
        assert_eq!(allowed_paths[0].plugin.as_str(), p("tmp"));

        #[cfg(not(windows))]
        {
            assert_eq!(allowed_paths[1].host.as_str(), p("var/log"));
            assert_eq!(allowed_paths[1].plugin.as_str(), "/plugin/logs");
        }

        assert_eq!(allowed_paths[2].host.as_str(), p("home/user/data"));
        assert_eq!(allowed_paths[2].plugin.as_str(), p("home/user/data"));

        assert_eq!(runtime_config.env_vars.as_ref().unwrap().len(), 2);
        assert_eq!(
            *runtime_config.memory_limit.as_ref().unwrap(),
            ByteSize::gb(1)
        );

        // Verify minimal plugin has no runtime config
        let minimal_plugin = config
            .plugins
            .get(&PluginName::try_from("minimal_plugin").unwrap())
            .unwrap();
        assert!(minimal_plugin.runtime_config.is_none());
    }

    #[test]
    fn test_load_valid_json_config() {
        let rt = Runtime::new().unwrap();

        // Read the test fixture file
        let path = Path::new("tests/fixtures/valid_config.json");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));

        assert!(config_result.is_ok(), "Failed to load valid JSON config");

        let config = config_result.unwrap();
        assert_eq!(config.plugins.len(), 3, "Expected 3 plugins in the config");

        // Verify plugin names
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("test_plugin").unwrap())
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("another_plugin").unwrap())
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("minimal_plugin").unwrap())
        );

        // Verify env vars
        let test_plugin = config
            .plugins
            .get(&PluginName::try_from("test_plugin").unwrap())
            .unwrap();
        let runtime_config = test_plugin.runtime_config.as_ref().unwrap();
        assert_eq!(runtime_config.env_vars.as_ref().unwrap()["DEBUG"], "true");
        assert_eq!(
            runtime_config.env_vars.as_ref().unwrap()["LOG_LEVEL"],
            "info"
        );
    }

    #[test]
    fn test_load_invalid_plugin_name() {
        let rt = Runtime::new().unwrap();

        // Read the test fixture file
        let path = Path::new("tests/fixtures/invalid_plugin_name.yaml");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_err(),
            "Expected error for invalid plugin name"
        );
    }

    #[test]
    fn test_load_invalid_url() {
        let rt = Runtime::new().unwrap();

        // Read the test fixture file
        let path = Path::new("tests/fixtures/invalid_url.yaml");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));
        assert!(config_result.is_err(), "Expected error for invalid URL");

        let error = config_result.unwrap_err();
        assert!(
            error.to_string().contains("not a valid url")
                || error.to_string().contains("invalid URL"),
            "Error should mention the invalid URL"
        );
    }

    #[test]
    fn test_load_invalid_structure() {
        let rt = Runtime::new().unwrap();

        // Read the test fixture file
        let path = Path::new("tests/fixtures/invalid_structure.yaml");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_err(),
            "Expected error for invalid structure"
        );
    }

    #[test]
    fn test_load_nonexistent_file() {
        let rt = Runtime::new().unwrap();

        // Create a path that doesn't exist
        let nonexistent_path = Path::new("/tmp/definitely_not_a_real_config_file_12345.yaml");

        let cli = Cli {
            config_file: Some(nonexistent_path.to_path_buf()),

            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_err(),
            "Expected error for nonexistent file"
        );

        let error = config_result.unwrap_err();
        assert!(
            error.to_string().contains("not found"),
            "Error should mention file not found"
        );
    }

    #[test]
    fn test_load_unsupported_extension() {
        let rt = Runtime::new().unwrap();

        let path = Path::new("tests/fixtures/unsupported_config.txt");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        // Load the config
        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_err(),
            "Expected error for unsupported extension"
        );

        let error = config_result.unwrap_err();
        assert!(
            error.to_string().contains("Unsupported config format"),
            "Error should mention unsupported format"
        );
    }

    #[test]
    fn test_auth_config_basic_serialization() {
        let auth_config = AuthConfig::Basic {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let serialized = serde_json::to_string(&auth_config).unwrap();
        let expected = r#"{"type":"basic","username":"testuser","password":"testpass"}"#;
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_auth_config_token_serialization() {
        let auth_config = AuthConfig::Token {
            token: "test-token-123".to_string(),
        };

        let serialized = serde_json::to_string(&auth_config).unwrap();
        let expected = r#"{"type":"token","token":"test-token-123"}"#;
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_auth_config_basic_deserialization() {
        let json = r#"{"type":"basic","username":"testuser","password":"testpass"}"#;
        let auth_config: AuthConfig = serde_json::from_str(json).unwrap();

        match auth_config {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Basic auth config"),
        }
    }

    #[test]
    fn test_auth_config_token_deserialization() {
        let json = r#"{"type":"token","token":"test-token-123"}"#;
        let auth_config: AuthConfig = serde_json::from_str(json).unwrap();

        match auth_config {
            AuthConfig::Token { token } => {
                assert_eq!(token, "test-token-123");
            }
            _ => panic!("Expected Token auth config"),
        }
    }

    #[test]
    fn test_auth_config_yaml_basic_deserialization() {
        let yaml = r#"
type: basic
username: testuser
password: testpass
"#;
        let auth_config: AuthConfig = serde_yaml::from_str(yaml).unwrap();

        match auth_config {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Basic auth config"),
        }
    }

    #[test]
    fn test_auth_config_yaml_token_deserialization() {
        let yaml = r#"
type: token
token: test-token-123
"#;
        let auth_config: AuthConfig = serde_yaml::from_str(yaml).unwrap();

        match auth_config {
            AuthConfig::Token { token } => {
                assert_eq!(token, "test-token-123");
            }
            _ => panic!("Expected Token auth config"),
        }
    }

    #[test]
    fn test_auth_config_invalid_type() {
        let json = r#"{"type":"invalid","data":"test"}"#;
        let result: Result<AuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for invalid auth type");
    }

    #[test]
    fn test_auth_config_missing_fields() {
        // Missing username for basic auth
        let json = r#"{"type":"basic","password":"testpass"}"#;
        let result: Result<AuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for missing username");

        // Missing password for basic auth
        let json = r#"{"type":"basic","username":"testuser"}"#;
        let result: Result<AuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for missing password");

        // Missing token for token auth
        let json = r#"{"type":"token"}"#;
        let result: Result<AuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for missing token");
    }

    #[test]
    fn test_config_with_auths_deserialization() {
        let json = r#"
{
  "auths": {
    "https://api.example.com": {
      "type": "basic",
      "username": "testuser",
      "password": "testpass"
    },
    "https://secure.api.com": {
      "type": "token",
      "token": "bearer-token-123"
    }
  },
  "plugins": {
    "test_plugin": {
      "url": "file:///path/to/plugin"
    }
  }
}
"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.auths.is_some());

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 2);

        let api_url = Url::parse("https://api.example.com").unwrap();
        let secure_url = Url::parse("https://secure.api.com").unwrap();

        assert!(auths.contains_key(&api_url));
        assert!(auths.contains_key(&secure_url));

        match &auths[&api_url] {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Basic auth for api.example.com"),
        }

        match &auths[&secure_url] {
            AuthConfig::Token { token } => {
                assert_eq!(token, "bearer-token-123");
            }
            _ => panic!("Expected Token auth for secure.api.com"),
        }
    }

    #[test]
    fn test_config_with_auths_yaml_deserialization() {
        let yaml = r#"
auths:
  "https://api.example.com":
    type: basic
    username: testuser
    password: testpass
  "https://secure.api.com":
    type: token
    token: bearer-token-123
plugins:
  test_plugin:
    url: "file:///path/to/plugin"
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.auths.is_some());

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 2);

        let api_url = Url::parse("https://api.example.com").unwrap();
        let secure_url = Url::parse("https://secure.api.com").unwrap();

        assert!(auths.contains_key(&api_url));
        assert!(auths.contains_key(&secure_url));
    }

    #[test]
    fn test_config_without_auths() {
        let json = r#"
{
  "plugins": {
    "test_plugin": {
      "url": "file:///path/to/plugin"
    }
  }
}
"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.auths.is_none());
        assert_eq!(config.plugins.len(), 1);
    }

    #[test]
    fn test_auth_config_clone() {
        let auth_config = AuthConfig::Basic {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let cloned = auth_config.clone();
        match cloned {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Basic auth config"),
        }
    }

    #[test]
    fn test_auth_config_debug_format() {
        let auth_config = AuthConfig::Token {
            token: "secret-token".to_string(),
        };

        let debug_str = format!("{auth_config:?}");
        assert!(debug_str.contains("Token"));
        assert!(debug_str.contains("secret-token"));
    }

    #[test]
    fn test_internal_auth_config_keyring_deserialization() {
        let json = r#"{"type":"keyring","service":"test-service","user":"test-user"}"#;
        let result: Result<InternalAuthConfig, _> = serde_json::from_str(json);

        // This should deserialize successfully as InternalAuthConfig
        assert!(result.is_ok());

        match result.unwrap() {
            InternalAuthConfig::Keyring(KeyringEntryId { service, user }) => {
                assert_eq!(service, "test-service");
                assert_eq!(user, "test-user");
            }
            _ => panic!("Expected Keyring auth config"),
        }
    }

    #[test]
    fn test_auth_config_empty_values() {
        // Test with empty username
        let json = r#"{"type":"basic","username":"","password":"testpass"}"#;
        let auth_config: AuthConfig = serde_json::from_str(json).unwrap();
        match auth_config {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Basic auth config"),
        }

        // Test with empty token
        let json = r#"{"type":"token","token":""}"#;
        let auth_config: AuthConfig = serde_json::from_str(json).unwrap();
        match auth_config {
            AuthConfig::Token { token } => {
                assert_eq!(token, "");
            }
            _ => panic!("Expected Token auth config"),
        }
    }

    #[test]
    fn test_load_config_with_auths_yaml() {
        let rt = Runtime::new().unwrap();
        let path = Path::new("tests/fixtures/config_with_auths.yaml");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Failed to load config with auths from YAML"
        );

        let config = config_result.unwrap();
        assert!(config.auths.is_some(), "Expected auths to be present");

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 4, "Expected 4 auth configurations");

        // Test basic auth
        let api_url = Url::parse("https://api.example.com").unwrap();
        assert!(auths.contains_key(&api_url));
        match &auths[&api_url] {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "testuser");
                assert_eq!(password, "testpass");
            }
            _ => panic!("Expected Basic auth for api.example.com"),
        }

        // Test token auth
        let secure_url = Url::parse("https://secure.api.com").unwrap();
        assert!(auths.contains_key(&secure_url));
        match &auths[&secure_url] {
            AuthConfig::Token { token } => {
                assert_eq!(token, "bearer-token-123");
            }
            _ => panic!("Expected Token auth for secure.api.com"),
        }
    }

    #[test]
    fn test_load_config_with_auths_json() {
        let rt = Runtime::new().unwrap();
        let path = Path::new("tests/fixtures/config_with_auths.json");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Failed to load config with auths from JSON"
        );

        let config = config_result.unwrap();
        assert!(config.auths.is_some(), "Expected auths to be present");

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 4, "Expected 4 auth configurations");

        // Test that all URLs are present
        let expected_urls = vec![
            "https://api.example.com",
            "https://secure.api.com",
            "https://private.registry.io",
            "https://oauth.service.com",
        ];

        for url_str in expected_urls {
            let url = Url::parse(url_str).unwrap();
            assert!(auths.contains_key(&url), "Missing auth for {url_str}");
        }
    }

    #[test]
    fn test_load_invalid_auth_config() {
        let rt = Runtime::new().unwrap();
        let path = Path::new("tests/fixtures/invalid_auth_config.yaml");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_err(),
            "Expected error for invalid auth config"
        );

        let error = config_result.unwrap_err();
        let error_msg = error.to_string();
        // The error should be related to deserialization
        assert!(
            error_msg.contains("unknown variant")
                || error_msg.contains("missing field")
                || error_msg.contains("invalid"),
            "Error should indicate invalid auth configuration: {error_msg}"
        );
    }

    #[test]
    fn test_auth_config_url_matching() {
        let mut auths = HashMap::new();

        // Add auth for specific API endpoint
        let api_url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            api_url,
            AuthConfig::Token {
                token: "api-token".to_string(),
            },
        );

        // Add auth for broader domain
        let domain_url = Url::parse("https://example.com").unwrap();
        auths.insert(
            domain_url,
            AuthConfig::Basic {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
        );

        let config = Config {
            auths: Some(auths),
            plugins: DashMap::new(),

            ..Default::default()
        };

        // Serialize and deserialize to test round-trip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert!(deserialized.auths.is_some());
        assert_eq!(deserialized.auths.unwrap().len(), 2);
    }

    #[test]
    fn test_auth_config_special_characters() {
        // Test with special characters in passwords and tokens
        let auth_basic = AuthConfig::Basic {
            username: "user@domain.com".to_string(),
            password: "p@ssw0rd!#$%".to_string(),
        };

        let auth_token = AuthConfig::Token {
            token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ".to_string(),
        };

        // Test serialization
        let basic_json = serde_json::to_string(&auth_basic).unwrap();
        let token_json = serde_json::to_string(&auth_token).unwrap();

        // Test deserialization
        let basic_deserialized: AuthConfig = serde_json::from_str(&basic_json).unwrap();
        let token_deserialized: AuthConfig = serde_json::from_str(&token_json).unwrap();

        match basic_deserialized {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "user@domain.com");
                assert_eq!(password, "p@ssw0rd!#$%");
            }
            _ => panic!("Expected Basic auth config"),
        }

        match token_deserialized {
            AuthConfig::Token { token } => {
                assert!(token.starts_with("eyJ"));
            }
            _ => panic!("Expected Token auth config"),
        }
    }

    #[test]
    fn test_config_auths_optional() {
        // Test config without auths field
        let json_without_auths = r#"
{
  "plugins": {
    "test_plugin": {
      "url": "file:///path/to/plugin"
    }
  }
}
"#;

        let config: Config = serde_json::from_str(json_without_auths).unwrap();
        assert!(config.auths.is_none());

        // Test config with empty auths
        let json_empty_auths = r#"
{
  "auths": {},
  "plugins": {
    "test_plugin": {
      "url": "file:///path/to/plugin"
    }
  }
}
"#;

        let config: Config = serde_json::from_str(json_empty_auths).unwrap();
        assert!(config.auths.is_some());
        assert_eq!(config.auths.unwrap().len(), 0);
    }

    #[test]
    fn test_keyring_auth_config_deserialization() {
        // Test that keyring config deserializes correctly as InternalAuthConfig
        let json = r#"{"type":"keyring","service":"test-service","user":"test-user"}"#;
        let internal_auth: InternalAuthConfig = serde_json::from_str(json).unwrap();

        match internal_auth {
            InternalAuthConfig::Keyring(KeyringEntryId { service, user }) => {
                assert_eq!(service, "test-service");
                assert_eq!(user, "test-user");
            }
            _ => panic!("Expected Keyring auth config"),
        }
    }

    #[test]
    fn test_documentation_example_yaml() {
        let rt = Runtime::new().unwrap();
        let path = Path::new("tests/fixtures/documentation_example.yaml");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Documentation YAML example should be valid"
        );

        let config = config_result.unwrap();

        // Verify auths are present and correct
        assert!(config.auths.is_some());
        let auths = config.auths.unwrap();
        assert_eq!(
            auths.len(),
            3,
            "Expected 3 auth configurations from documentation example"
        );

        // Verify basic auth
        let registry_url = Url::parse("https://private.registry.io").unwrap();
        match &auths[&registry_url] {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "registry-user");
                assert_eq!(password, "registry-pass");
            }
            _ => panic!("Expected Basic auth for private.registry.io"),
        }

        // Verify token auth
        let github_url = Url::parse("https://api.github.com").unwrap();
        match &auths[&github_url] {
            AuthConfig::Token { token } => {
                assert_eq!(token, "ghp_1234567890abcdef");
            }
            _ => panic!("Expected Token auth for api.github.com"),
        }

        // Verify plugins
        assert_eq!(
            config.plugins.len(),
            3,
            "Expected 3 plugins from documentation example"
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("time").unwrap())
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("myip").unwrap())
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName::try_from("private_plugin").unwrap())
        );

        // Verify private plugin config
        let private_plugin = config
            .plugins
            .get(&PluginName::try_from("private_plugin").unwrap())
            .unwrap();
        assert_eq!(
            private_plugin.url.to_string(),
            "https://private.registry.io/my_plugin"
        );
        assert!(private_plugin.runtime_config.is_some());
    }

    #[test]
    fn test_documentation_example_json() {
        let rt = Runtime::new().unwrap();
        let path = Path::new("tests/fixtures/documentation_example.json");

        let cli = Cli {
            config_file: Some(path.to_path_buf()),

            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Documentation JSON example should be valid"
        );

        let config = config_result.unwrap();

        // Verify auths are present and correct
        assert!(config.auths.is_some());
        let auths = config.auths.unwrap();
        assert_eq!(
            auths.len(),
            3,
            "Expected 3 auth configurations from documentation example"
        );

        // Verify all auth URLs are present
        let expected_auth_urls = vec![
            "https://private.registry.io",
            "https://api.github.com",
            "https://enterprise.api.com",
        ];

        for url_str in expected_auth_urls {
            let url = Url::parse(url_str).unwrap();
            assert!(auths.contains_key(&url), "Missing auth for {url_str}");
        }

        // Verify plugins match the documentation
        assert_eq!(config.plugins.len(), 3);

        let myip_plugin = config
            .plugins
            .get(&PluginName::try_from("myip").unwrap())
            .unwrap();
        let runtime_config = myip_plugin.runtime_config.as_ref().unwrap();
        assert_eq!(runtime_config.env_vars.as_ref().unwrap()["FOO"], "bar");
        assert_eq!(
            *runtime_config.memory_limit.as_ref().unwrap(),
            ByteSize::mib(512)
        );
    }

    #[test]
    fn test_url_prefix_matching_from_documentation() {
        // Test the URL matching behavior described in documentation
        let yaml = r#"
auths:
  "https://example.com":
    type: basic
    username: "broad-user"
    password: "broad-pass"
  "https://example.com/api":
    type: token
    token: "api-token"
  "https://example.com/api/v1":
    type: basic
    username: "v1-user"
    password: "v1-pass"
plugins:
  test_plugin:
    url: "file:///test"
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.auths.is_some());

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 3);

        // Verify all three auth configs are present
        let base_url = Url::parse("https://example.com").unwrap();
        let api_url = Url::parse("https://example.com/api").unwrap();
        let v1_url = Url::parse("https://example.com/api/v1").unwrap();

        assert!(auths.contains_key(&base_url));
        assert!(auths.contains_key(&api_url));
        assert!(auths.contains_key(&v1_url));

        // Verify the specific auth types match documentation
        match &auths[&base_url] {
            AuthConfig::Basic { username, .. } => {
                assert_eq!(username, "broad-user");
            }
            _ => panic!("Expected Basic auth for base URL"),
        }

        match &auths[&api_url] {
            AuthConfig::Token { token } => {
                assert_eq!(token, "api-token");
            }
            _ => panic!("Expected Token auth for API URL"),
        }

        match &auths[&v1_url] {
            AuthConfig::Basic { username, .. } => {
                assert_eq!(username, "v1-user");
            }
            _ => panic!("Expected Basic auth for v1 URL"),
        }
    }

    #[test]
    fn test_keyring_json_format_validation() {
        // Test that the JSON formats shown in keyring documentation examples are valid

        // Test basic auth JSON format from documentation
        let basic_json = r#"{"type":"basic","username":"actual-user","password":"actual-pass"}"#;
        let basic_auth: AuthConfig = serde_json::from_str(basic_json).unwrap();

        match basic_auth {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "actual-user");
                assert_eq!(password, "actual-pass");
            }
            _ => panic!("Expected Basic auth config from keyring JSON"),
        }

        // Test token auth JSON format from documentation
        let token_json = r#"{"type":"token","token":"actual-bearer-token"}"#;
        let token_auth: AuthConfig = serde_json::from_str(token_json).unwrap();

        match token_auth {
            AuthConfig::Token { token } => {
                assert_eq!(token, "actual-bearer-token");
            }
            _ => panic!("Expected Token auth config from keyring JSON"),
        }

        // Test JWT-like token from documentation
        let jwt_json = r#"{"type":"token","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}"#;
        let jwt_auth: AuthConfig = serde_json::from_str(jwt_json).unwrap();

        match jwt_auth {
            AuthConfig::Token { token } => {
                assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
            }
            _ => panic!("Expected Token auth config from keyring JWT JSON"),
        }

        // Test corporate example from documentation
        let corp_json = r#"{"type":"basic","username":"corp_user","password":"corp_secret"}"#;
        let corp_auth: AuthConfig = serde_json::from_str(corp_json).unwrap();

        match corp_auth {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "corp_user");
                assert_eq!(password, "corp_secret");
            }
            _ => panic!("Expected Basic auth config from corporate JSON"),
        }
    }

    #[test]
    #[ignore] // Requires system keyring access - run with `cargo test -- --ignored`
    fn test_keyring_auth_integration() {
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Generate unique service and user names to avoid conflicts
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let service_name = format!("hyper-mcp-test-{timestamp}");
        let user_name = format!("test-user-{timestamp}");

        // Test auth config to store in keyring
        let test_auth_json =
            r#"{"type":"basic","username":"keyring-test-user","password":"keyring-test-pass"}"#;

        // Platform-specific keyring operations
        let (add_result, remove_result) = if cfg!(target_os = "macos") {
            // macOS using security command
            let add_result = Command::new("security")
                .args([
                    "add-generic-password",
                    "-a",
                    &user_name,
                    "-s",
                    &service_name,
                    "-w",
                    test_auth_json,
                ])
                .output();

            let remove_result = Command::new("security")
                .args([
                    "delete-generic-password",
                    "-a",
                    &user_name,
                    "-s",
                    &service_name,
                ])
                .output();

            (add_result, remove_result)
        } else if cfg!(target_os = "linux") {
            // Linux using secret-tool
            let add_result = Command::new("bash")
                .args([
                    "-c",
                    &format!("echo '{test_auth_json}' | secret-tool store --label='hyper-mcp test' service '{service_name}' username '{user_name}'"),
                ])
                .output();

            let remove_result = Command::new("secret-tool")
                .args(["clear", "service", &service_name, "username", &user_name])
                .output();

            (add_result, remove_result)
        } else if cfg!(target_os = "windows") {
            // Windows using cmdkey
            let escaped_json = test_auth_json.replace("\"", "\\\"");
            let add_result = Command::new("cmdkey")
                .args([
                    &format!("/generic:{service_name}"),
                    &format!("/user:{user_name}"),
                    &format!("/pass:{escaped_json}"),
                ])
                .output();

            let remove_result = Command::new("cmdkey")
                .args([&format!("/delete:{service_name}")])
                .output();

            (add_result, remove_result)
        } else {
            // Unsupported platform
            println!(
                "Keyring test skipped on unsupported platform: {}",
                std::env::consts::OS
            );
            return;
        };

        // Try to add the secret to keyring
        let add_output = match add_result {
            Ok(output) => output,
            Err(e) => {
                println!("Failed to execute keyring add command: {e}. Skipping test.");
                return;
            }
        };

        if !add_output.status.success() {
            println!(
                "Failed to add secret to keyring (exit code: {}). stdout: {}, stderr: {}. Skipping test.",
                add_output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&add_output.stdout),
                String::from_utf8_lossy(&add_output.stderr)
            );
            return;
        }

        // Test keyring auth deserialization
        let keyring_config_json =
            format!(r#"{{"type":"keyring","service":"{service_name}","user":"{user_name}"}}"#);

        let test_result = std::panic::catch_unwind(|| {
            let internal_auth: InternalAuthConfig =
                serde_json::from_str(&keyring_config_json).unwrap();

            // This should trigger the keyring lookup and deserialize to AuthConfig
            match internal_auth {
                InternalAuthConfig::Keyring(KeyringEntryId { service, user }) => {
                    assert_eq!(service, service_name);
                    assert_eq!(user, user_name);

                    // Test the actual keyring deserialization through AuthConfig
                    let auth_config: Result<AuthConfig, _> =
                        serde_json::from_str(&keyring_config_json);

                    match auth_config {
                        Ok(AuthConfig::Basic { username, password }) => {
                            assert_eq!(username, "keyring-test-user");
                            assert_eq!(password, "keyring-test-pass");
                        }
                        Ok(AuthConfig::Token { .. }) => {
                            panic!("Expected Basic auth from keyring, got Token");
                        }
                        Err(e) => {
                            println!(
                                "Keyring lookup failed (this is expected if keyring service is not available): {e}"
                            );
                        }
                    }
                }
                _ => panic!("Expected Keyring internal auth config"),
            }
        });

        // Always attempt cleanup regardless of test result
        if let Ok(output) = remove_result {
            if !output.status.success() {
                println!(
                    "Warning: Failed to remove test secret from keyring (exit code: {}). stdout: {}, stderr: {}",
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Re-panic if the test failed
        if let Err(panic_info) = test_result {
            std::panic::resume_unwind(panic_info);
        }
    }

    #[test]
    #[ignore] // Requires system keyring access and file creation - run with `cargo test -- --ignored`
    fn test_keyring_auth_complete_config_integration() {
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::fs;

        let rt = Runtime::new().unwrap();

        // Generate unique identifiers
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let service_name = format!("hyper-mcp-config-test-{timestamp}");
        let user_name = format!("config-test-user-{timestamp}");
        let temp_config_path = format!("test_config_{timestamp}.yaml");

        // Auth config to store in keyring
        let keyring_auth_json =
            r#"{"type":"token","token":"test-keyring-token-from-complete-config"}"#;

        // Create complete config with keyring auth
        let config_content = format!(
            r#"
auths:
  "https://keyring-test.example.com":
    type: keyring
    service: "{service_name}"
    user: "{user_name}"
  "https://basic-test.example.com":
    type: basic
    username: "basic-user"
    password: "basic-pass"
plugins:
  test_plugin:
    url: "file:///test/plugin"
    runtime_config:
      allowed_hosts:
        - "keyring-test.example.com"
        - "basic-test.example.com"
"#
        );

        // Platform-specific keyring operations
        let (add_result, remove_result) = if cfg!(target_os = "macos") {
            let add_result = Command::new("security")
                .args([
                    "add-generic-password",
                    "-a",
                    &user_name,
                    "-s",
                    &service_name,
                    "-w",
                    keyring_auth_json,
                ])
                .output();

            let remove_result = Command::new("security")
                .args([
                    "delete-generic-password",
                    "-a",
                    &user_name,
                    "-s",
                    &service_name,
                ])
                .output();

            (add_result, remove_result)
        } else if cfg!(target_os = "linux") {
            let add_result = Command::new("bash")
                .args([
                    "-c",
                    &format!(
                        "echo '{keyring_auth_json}' | secret-tool store --label='hyper-mcp complete config test' service '{service_name}' username '{user_name}'"
                    ),
                ])
                .output();

            let remove_result = Command::new("secret-tool")
                .args(["clear", "service", &service_name, "username", &user_name])
                .output();

            (add_result, remove_result)
        } else if cfg!(target_os = "windows") {
            let escaped_json = keyring_auth_json.replace("\"", "\\\"");
            let add_result = Command::new("cmdkey")
                .args([
                    &format!("/generic:{service_name}"),
                    &format!("/user:{user_name}"),
                    &format!("/pass:{escaped_json}"),
                ])
                .output();

            let remove_result = Command::new("cmdkey")
                .args([&format!("/delete:{service_name}")])
                .output();

            (add_result, remove_result)
        } else {
            println!(
                "Keyring integration test skipped on unsupported platform: {}",
                std::env::consts::OS
            );
            return;
        };

        // Create temporary config file
        let config_path = Path::new(&temp_config_path);
        let write_result = rt.block_on(fs::write(config_path, config_content));
        if write_result.is_err() {
            println!("Failed to create temporary config file. Skipping test.");
            return;
        }

        // Try to add secret to keyring
        let add_output = match add_result {
            Ok(output) => output,
            Err(e) => {
                println!("Failed to execute keyring add command: {e}. Skipping test.");
                let _ = rt.block_on(fs::remove_file(config_path));
                return;
            }
        };

        if !add_output.status.success() {
            println!(
                "Failed to add secret to keyring (exit code: {}). stdout: {}, stderr: {}. Skipping test.",
                add_output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&add_output.stdout),
                String::from_utf8_lossy(&add_output.stderr)
            );
            let _ = rt.block_on(fs::remove_file(config_path));
            return;
        }

        let cli = Cli {
            config_file: Some(config_path.to_path_buf()),

            ..Default::default()
        };

        // Test loading the config file (this should trigger keyring lookup)
        let load_result = rt.block_on(Config::load(&cli));

        // Cleanup keyring entry before checking results
        if let Ok(output) = remove_result {
            if !output.status.success() {
                println!(
                    "Warning: Failed to remove test secret from keyring (exit code: {}). stdout: {}, stderr: {}. Manual cleanup may be required.",
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Cleanup temporary config file
        let _ = rt.block_on(fs::remove_file(config_path));

        // Now check the test results
        match load_result {
            Ok(config) => {
                // Verify auths are present
                assert!(
                    config.auths.is_some(),
                    "Expected auths to be present in loaded config"
                );
                let auths = config.auths.unwrap();
                assert_eq!(auths.len(), 2, "Expected 2 auth configurations");

                // Verify keyring auth was resolved successfully
                let keyring_url = Url::parse("https://keyring-test.example.com").unwrap();
                assert!(
                    auths.contains_key(&keyring_url),
                    "Expected keyring auth URL to be present"
                );

                match &auths[&keyring_url] {
                    AuthConfig::Token { token } => {
                        assert_eq!(
                            token, "test-keyring-token-from-complete-config",
                            "Token from keyring should match stored value"
                        );
                    }
                    _ => panic!("Expected Token auth from keyring resolution"),
                }

                // Verify basic auth still works alongside keyring auth
                let basic_url = Url::parse("https://basic-test.example.com").unwrap();
                assert!(
                    auths.contains_key(&basic_url),
                    "Expected basic auth URL to be present"
                );

                match &auths[&basic_url] {
                    AuthConfig::Basic { username, password } => {
                        assert_eq!(username, "basic-user");
                        assert_eq!(password, "basic-pass");
                    }
                    _ => panic!("Expected Basic auth config"),
                }

                // Verify plugins loaded correctly
                assert_eq!(config.plugins.len(), 1, "Expected 1 plugin in config");
                assert!(
                    config
                        .plugins
                        .contains_key(&PluginName::try_from("test_plugin").unwrap())
                );

                println!(
                    "✅ Keyring integration test passed on platform: {}",
                    std::env::consts::OS
                );
            }
            Err(e) => {
                // Check if this is a keyring-related error
                let error_msg = e.to_string();
                if error_msg.contains("keyring") || error_msg.contains("secure storage") {
                    println!(
                        "Keyring lookup failed (keyring service may not be available): {e}. This is acceptable for CI environments."
                    );
                } else {
                    panic!("Unexpected error loading config with keyring auth: {e}");
                }
            }
        }
    }

    #[test]
    #[ignore] // Requires system keyring access - run with `cargo test -- --ignored`
    fn test_keyring_auth_direct_deserialization() {
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Generate unique service and user names to avoid conflicts
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let service_name = format!("hyper-mcp-direct-test-{timestamp}");
        let user_name = format!("direct-test-user-{timestamp}");

        // Test auth config to store in keyring (basic auth this time)
        let test_auth_json =
            r#"{"type":"basic","username":"direct-keyring-user","password":"direct-keyring-pass"}"#;

        // Determine platform and execute appropriate keyring commands
        if cfg!(target_os = "macos") {
            // macOS: Add and test, then cleanup
            let add_cmd = Command::new("security")
                .args([
                    "add-generic-password",
                    "-a",
                    &user_name,
                    "-s",
                    &service_name,
                    "-w",
                    test_auth_json,
                ])
                .output();

            if let Ok(add_output) = add_cmd {
                if add_output.status.success() {
                    // Test the keyring deserialization
                    let keyring_config_json = format!(
                        r#"{{"type":"keyring","service":"{service_name}","user":"{user_name}"}}"#
                    );

                    let auth_result: Result<AuthConfig, _> =
                        serde_json::from_str(&keyring_config_json);

                    // Cleanup first
                    let _ = Command::new("security")
                        .args([
                            "delete-generic-password",
                            "-a",
                            &user_name,
                            "-s",
                            &service_name,
                        ])
                        .output();

                    // Verify result
                    match auth_result {
                        Ok(AuthConfig::Basic { username, password }) => {
                            assert_eq!(username, "direct-keyring-user");
                            assert_eq!(password, "direct-keyring-pass");
                            println!("✅ macOS keyring direct deserialization test passed");
                        }
                        Ok(_) => panic!("Expected Basic auth from keyring"),
                        Err(e) => {
                            println!(
                                "Keyring lookup failed on macOS (may not be available in CI): {e}"
                            );
                        }
                    }
                } else {
                    println!("Failed to add secret to macOS keyring, skipping test");
                }
            }
        } else if cfg!(target_os = "linux") {
            // Linux: Add and test, then cleanup
            let add_cmd = Command::new("bash")
                .args([
                    "-c",
                    &format!(
                        "echo '{test_auth_json}' | secret-tool store --label='hyper-mcp direct test' service '{service_name}' username '{user_name}'"
                    ),
                ])
                .output();

            if let Ok(add_output) = add_cmd {
                if add_output.status.success() {
                    // Test the keyring deserialization
                    let keyring_config_json = format!(
                        r#"{{"type":"keyring","service":"{service_name}","user":"{user_name}"}}"#
                    );

                    let auth_result: Result<AuthConfig, _> =
                        serde_json::from_str(&keyring_config_json);

                    // Cleanup first
                    let _ = Command::new("secret-tool")
                        .args(["clear", "service", &service_name, "username", &user_name])
                        .output();

                    // Verify result
                    match auth_result {
                        Ok(AuthConfig::Basic { username, password }) => {
                            assert_eq!(username, "direct-keyring-user");
                            assert_eq!(password, "direct-keyring-pass");
                            println!("✅ Linux keyring direct deserialization test passed");
                        }
                        Ok(_) => panic!("Expected Basic auth from keyring"),
                        Err(e) => {
                            println!(
                                "Keyring lookup failed on Linux (may not be available in CI): {e}"
                            );
                        }
                    }
                } else {
                    println!("Failed to add secret to Linux keyring, skipping test");
                }
            }
        } else if cfg!(target_os = "windows") {
            // Windows: Add and test, then cleanup
            let escaped_json = test_auth_json.replace("\"", "\\\"");
            let add_cmd = Command::new("cmdkey")
                .args([
                    &format!("/generic:{service_name}"),
                    &format!("/user:{user_name}"),
                    &format!("/pass:{escaped_json}"),
                ])
                .output();

            if let Ok(add_output) = add_cmd {
                if add_output.status.success() {
                    // Test the keyring deserialization
                    let keyring_config_json = format!(
                        r#"{{"type":"keyring","service":"{service_name}","user":"{user_name}"}}"#
                    );

                    let auth_result: Result<AuthConfig, _> =
                        serde_json::from_str(&keyring_config_json);

                    // Cleanup first
                    let _ = Command::new("cmdkey")
                        .args([&format!("/delete:{service_name}")])
                        .output();

                    // Verify result
                    match auth_result {
                        Ok(AuthConfig::Basic { username, password }) => {
                            assert_eq!(username, "direct-keyring-user");
                            assert_eq!(password, "direct-keyring-pass");
                            println!("✅ Windows keyring direct deserialization test passed");
                        }
                        Ok(_) => panic!("Expected Basic auth from keyring"),
                        Err(e) => {
                            println!(
                                "Keyring lookup failed on Windows (may not be available in CI): {e}"
                            );
                        }
                    }
                } else {
                    println!("Failed to add secret to Windows keyring, skipping test");
                }
            }
        } else {
            println!(
                "Direct keyring deserialization test skipped on unsupported platform: {}",
                std::env::consts::OS
            );
        }
    }

    #[test]
    #[ignore]
    fn test_platform_detection_and_keyring_tool_availability() {
        use std::process::Command;

        println!(
            "Running platform detection test on: {}",
            std::env::consts::OS
        );

        if cfg!(target_os = "macos") {
            // Test macOS security command availability
            let security_check = Command::new("security").arg("help").output();

            match security_check {
                Ok(output) => {
                    if output.status.success() {
                        println!("✅ macOS security command is available");

                        // Test that we can list keychains (read-only operation)
                        let list_check = Command::new("security").args(["list-keychains"]).output();
                        match list_check {
                            Ok(list_output) if list_output.status.success() => {
                                println!("✅ macOS keychain access is functional");
                            }
                            _ => {
                                println!("⚠️  macOS keychain access may be limited");
                            }
                        }
                    } else {
                        println!("❌ macOS security command failed");
                    }
                }
                Err(e) => {
                    println!("❌ macOS security command not found: {e}");
                }
            }
        } else if cfg!(target_os = "linux") {
            // Test Linux secret-tool availability
            let secret_tool_check = Command::new("secret-tool").arg("--help").output();

            match secret_tool_check {
                Ok(output) => {
                    if output.status.success() {
                        println!("✅ Linux secret-tool is available");
                    } else {
                        println!("❌ Linux secret-tool command failed");
                    }
                }
                Err(e) => {
                    println!(
                        "❌ Linux secret-tool not found: {e}. Install with: sudo apt-get install libsecret-tools"
                    );
                }
            }

            // Check if dbus session is available (required for keyring)
            let dbus_check = Command::new("dbus-send")
                .args([
                    "--session",
                    "--dest=org.freedesktop.DBus",
                    "--print-reply",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus.ListNames",
                ])
                .output();

            match dbus_check {
                Ok(output) if output.status.success() => {
                    println!("✅ Linux D-Bus session is available");
                }
                _ => {
                    println!("⚠️  Linux D-Bus session may not be available (required for keyring)");
                }
            }
        } else if cfg!(target_os = "windows") {
            // Test Windows cmdkey availability
            let cmdkey_check = Command::new("cmdkey").arg("/?").output();

            match cmdkey_check {
                Ok(output) => {
                    if output.status.success() {
                        println!("✅ Windows cmdkey is available");

                        // Test that we can list credentials (read-only operation)
                        let list_check = Command::new("cmdkey").args(["/list"]).output();
                        match list_check {
                            Ok(list_output) if list_output.status.success() => {
                                println!("✅ Windows Credential Manager access is functional");
                            }
                            _ => {
                                println!("⚠️  Windows Credential Manager access may be limited");
                            }
                        }
                    } else {
                        println!("❌ Windows cmdkey command failed");
                    }
                }
                Err(e) => {
                    println!("❌ Windows cmdkey not found: {e}");
                }
            }
        } else {
            println!(
                "ℹ️  Platform {} is not supported for keyring authentication",
                std::env::consts::OS
            );
        }
    }

    #[test]
    fn test_keyring_auth_config_missing_service() {
        let json = r#"{"type":"keyring","user":"test-user"}"#;
        let result: Result<InternalAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for missing service field");
    }

    #[test]
    fn test_keyring_auth_config_missing_user() {
        let json = r#"{"type":"keyring","service":"test-service"}"#;
        let result: Result<InternalAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for missing user field");
    }

    #[test]
    fn test_keyring_auth_config_empty_values() {
        let json = r#"{"type":"keyring","service":"","user":"test-user"}"#;
        let internal_auth: InternalAuthConfig = serde_json::from_str(json).unwrap();

        match internal_auth {
            InternalAuthConfig::Keyring(KeyringEntryId { service, user }) => {
                assert_eq!(service, "");
                assert_eq!(user, "test-user");
            }
            _ => panic!("Expected Keyring auth config"),
        }
    }

    #[test]
    fn test_mixed_auth_types_config() {
        let json = r#"
{
  "auths": {
    "https://basic.example.com": {
      "type": "basic",
      "username": "basicuser",
      "password": "basicpass"
    },
    "https://token.example.com": {
      "type": "token",
      "token": "token-123"
    }
  },
  "plugins": {
    "test_plugin": {
      "url": "file:///path/to/plugin"
    }
  }
}
"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.auths.is_some());

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 2);

        // Verify we have both auth types
        let basic_url = Url::parse("https://basic.example.com").unwrap();
        let token_url = Url::parse("https://token.example.com").unwrap();

        match &auths[&basic_url] {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "basicuser");
                assert_eq!(password, "basicpass");
            }
            _ => panic!("Expected Basic auth"),
        }

        match &auths[&token_url] {
            AuthConfig::Token { token } => {
                assert_eq!(token, "token-123");
            }
            _ => panic!("Expected Token auth"),
        }
    }

    #[test]
    fn test_auth_config_yaml_mixed_types() {
        let yaml = r#"
auths:
  "https://basic.example.com":
    type: basic
    username: basicuser
    password: basicpass
  "https://token.example.com":
    type: token
    token: token-123
plugins:
  test_plugin:
    url: "file:///path/to/plugin"
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.auths.is_some());

        let auths = config.auths.unwrap();
        assert_eq!(auths.len(), 2);
    }

    #[test]
    fn test_auth_config_special_urls() {
        let mut auths = HashMap::new();

        // Test with localhost URL
        let localhost_url = Url::parse("http://localhost:8080").unwrap();
        auths.insert(
            localhost_url.clone(),
            AuthConfig::Basic {
                username: "localuser".to_string(),
                password: "localpass".to_string(),
            },
        );

        // Test with IP address URL
        let ip_url = Url::parse("https://192.168.1.100:443").unwrap();
        auths.insert(
            ip_url.clone(),
            AuthConfig::Token {
                token: "ip-token".to_string(),
            },
        );

        // Test with custom port
        let custom_port_url = Url::parse("https://api.example.com:9000").unwrap();
        auths.insert(
            custom_port_url.clone(),
            AuthConfig::Basic {
                username: "portuser".to_string(),
                password: "portpass".to_string(),
            },
        );

        let config = Config {
            auths: Some(auths),
            plugins: DashMap::new(),

            ..Default::default()
        };

        // Test serialization and deserialization round-trip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert!(deserialized.auths.is_some());
        let deserialized_auths = deserialized.auths.unwrap();
        assert_eq!(deserialized_auths.len(), 3);

        assert!(deserialized_auths.contains_key(&localhost_url));
        assert!(deserialized_auths.contains_key(&ip_url));
        assert!(deserialized_auths.contains_key(&custom_port_url));
    }

    #[test]
    fn test_auth_config_unicode_values() {
        // Test with unicode characters in credentials
        let auth_config = AuthConfig::Basic {
            username: "用户名".to_string(),
            password: "密码🔐".to_string(),
        };

        let json = serde_json::to_string(&auth_config).unwrap();
        let deserialized: AuthConfig = serde_json::from_str(&json).unwrap();

        match deserialized {
            AuthConfig::Basic { username, password } => {
                assert_eq!(username, "用户名");
                assert_eq!(password, "密码🔐");
            }
            _ => panic!("Expected Basic auth config"),
        }
    }

    #[test]
    fn test_auth_config_long_token() {
        // Test with very long token (JWT-like)
        let long_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzAyODYyNjMifQ.eyJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImV4cCI6MTYzNzI4NjI2MywiaWF0IjoxNjM3Mjc5MDYzLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature_here_would_be_much_longer";

        let auth_config = AuthConfig::Token {
            token: long_token.to_string(),
        };

        let json = serde_json::to_string(&auth_config).unwrap();
        let deserialized: AuthConfig = serde_json::from_str(&json).unwrap();

        match deserialized {
            AuthConfig::Token { token } => {
                assert_eq!(token, long_token);
                assert!(token.len() > 200);
            }
            _ => panic!("Expected Token auth config"),
        }
    }

    // Tests for skip_tools Option<RegexSet> functionality
    #[test]
    fn test_skip_tools_none() {
        let runtime_config = RuntimeConfig::default();

        // Test serialization
        let json = serde_json::to_string(&runtime_config).unwrap();
        assert!(json.contains("\"skip_tools\":null"));

        // Test deserialization
        let deserialized: RuntimeConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.skip_tools.is_none());
    }

    #[test]
    fn test_skip_tools_some_basic() {
        let json = r#"{
            "skip_tools": ["tool1", "tool2", "tool3"]
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        assert_eq!(skip_tools.len(), 3);
        assert!(skip_tools.is_match("tool1"));
        assert!(skip_tools.is_match("tool2"));
        assert!(skip_tools.is_match("tool3"));
        assert!(!skip_tools.is_match("tool4"));
        assert!(!skip_tools.is_match("tool1_extended"));
    }

    #[test]
    fn test_skip_tools_regex_patterns() {
        let json = r#"{
            "skip_tools": ["tool.*", "debug_.*", "test_[0-9]+"]
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        // Test wildcard patterns
        assert!(skip_tools.is_match("tool1"));
        assert!(skip_tools.is_match("tool_anything"));
        assert!(skip_tools.is_match("toolbox"));

        // Test prefix patterns
        assert!(skip_tools.is_match("debug_info"));
        assert!(skip_tools.is_match("debug_error"));

        // Test numbered patterns
        assert!(skip_tools.is_match("test_1"));
        assert!(skip_tools.is_match("test_99"));

        // Test non-matches
        assert!(!skip_tools.is_match("my_tool"));
        assert!(!skip_tools.is_match("debug"));
        assert!(!skip_tools.is_match("test_abc"));
        // "tool" should match "tool.*" pattern since it becomes "^tool.*$"
        assert!(skip_tools.is_match("tool"));
    }

    #[test]
    fn test_skip_tools_anchoring_behavior() {
        let json = r#"{
            "skip_tools": ["tool", "^prefix_.*", ".*_suffix$", "^exact_match$"]
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        // "tool" should be auto-anchored to "^tool$"
        assert!(skip_tools.is_match("tool"));
        assert!(!skip_tools.is_match("tool_extended"));
        assert!(!skip_tools.is_match("my_tool"));

        // "^prefix_.*" should match anything starting with "prefix_"
        assert!(skip_tools.is_match("prefix_anything"));
        assert!(skip_tools.is_match("prefix_"));
        assert!(!skip_tools.is_match("my_prefix_tool"));

        // ".*_suffix$" should match anything ending with "_suffix"
        assert!(skip_tools.is_match("any_suffix"));
        assert!(skip_tools.is_match("_suffix"));
        assert!(!skip_tools.is_match("suffix_extended"));

        // "^exact_match$" should only match exactly "exact_match"
        assert!(skip_tools.is_match("exact_match"));
        assert!(!skip_tools.is_match("exact_match_extended"));
        // "prefix_exact_match" matches "^prefix_.*" pattern, not "^exact_match$"
        assert!(skip_tools.is_match("prefix_exact_match"));
    }

    #[test]
    fn test_skip_tools_serialization_roundtrip() {
        let original_patterns = vec![
            "tool1".to_string(),
            "tool.*".to_string(),
            "debug_.*".to_string(),
        ];
        let regex_set = RegexSet::new(&original_patterns).unwrap();

        let runtime_config = RuntimeConfig {
            skip_tools: Some(regex_set),

            ..Default::default()
        };

        // Serialize
        let json = serde_json::to_string(&runtime_config).unwrap();

        // Deserialize
        let deserialized: RuntimeConfig = serde_json::from_str(&json).unwrap();
        let skip_tools = deserialized.skip_tools.as_ref().unwrap();

        // Verify functionality is preserved
        assert!(skip_tools.is_match("tool1"));
        assert!(skip_tools.is_match("tool_anything"));
        assert!(skip_tools.is_match("debug_info"));
        assert!(!skip_tools.is_match("other_tool"));
    }

    #[test]
    fn test_skip_tools_yaml_deserialization() {
        let yaml = r#"
skip_tools:
  - "tool1"
  - "tool.*"
  - "debug_.*"
allowed_hosts:
  - "example.com"
"#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        assert!(skip_tools.is_match("tool1"));
        assert!(skip_tools.is_match("tool_test"));
        assert!(skip_tools.is_match("debug_info"));
        assert!(!skip_tools.is_match("other"));
    }

    #[test]
    fn test_skip_tools_invalid_regex() {
        let json = r#"{
            "skip_tools": ["valid_tool", "[unclosed_bracket", "another_valid"]
        }"#;

        let result: Result<RuntimeConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("regex") || error_msg.contains("bracket"));
    }

    #[test]
    fn test_skip_tools_empty_patterns() {
        let json = r#"{
            "skip_tools": []
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        assert_eq!(skip_tools.len(), 0);
        assert!(!skip_tools.is_match("anything"));
    }

    #[test]
    fn test_skip_tools_special_regex_characters() {
        let json = r#"{
            "skip_tools": ["tool\\.exe", "script\\?", "temp\\*file"]
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        // Test literal matching of special characters
        assert!(skip_tools.is_match("tool.exe"));
        assert!(skip_tools.is_match("script?"));
        assert!(skip_tools.is_match("temp*file"));

        // These should not match due to anchoring
        assert!(!skip_tools.is_match("my_tool.exe"));
        assert!(!skip_tools.is_match("script?.bat"));
    }

    #[test]
    fn test_skip_tools_case_sensitivity() {
        let json = r#"{
            "skip_tools": ["Tool", "DEBUG.*"]
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let skip_tools = runtime_config.skip_tools.as_ref().unwrap();

        // RegexSet is case sensitive by default
        assert!(skip_tools.is_match("Tool"));
        assert!(!skip_tools.is_match("tool"));
        assert!(!skip_tools.is_match("TOOL"));

        assert!(skip_tools.is_match("DEBUG_info"));
        assert!(!skip_tools.is_match("debug_info"));
    }

    #[test]
    fn test_skip_tools_default_behavior() {
        // Test that skip_tools defaults to None when not specified
        let json = r#"{
            "allowed_hosts": ["example.com"]
        }"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        assert!(runtime_config.skip_tools.is_none());
    }

    #[test]
    fn test_skip_tools_matching_functionality() {
        let patterns = vec![
            "exact".to_string(),
            "prefix.*".to_string(),
            ".*suffix".to_string(),
        ];
        let regex_set = RegexSet::new(
            patterns
                .iter()
                .map(|p| format!("^{}$", p))
                .collect::<Vec<_>>(),
        )
        .unwrap();

        // Test exact match
        assert!(regex_set.is_match("exact"));
        assert!(!regex_set.is_match("exact_more"));

        // Test prefix match
        assert!(regex_set.is_match("prefix123"));
        assert!(regex_set.is_match("prefixABC"));
        assert!(!regex_set.is_match("not_prefix123"));

        // Test suffix match
        assert!(regex_set.is_match("anysuffix"));
        assert!(regex_set.is_match("123suffix"));
        assert!(!regex_set.is_match("suffix_more"));
    }

    #[test]
    fn test_skip_tools_examples_integration() {
        use std::io::Write;

        let rt = Runtime::new().unwrap();

        // Create temp directories so allowed_paths host validation passes
        let base = TempDir::new().unwrap();
        let b = base.path();
        for d in &["tmp", "var/log", "home/user/data"] {
            std::fs::create_dir_all(b.join(d)).unwrap();
        }
        let p = |s: &str| -> String { b.join(s).to_str().unwrap().to_string() };

        // Read the original fixture and replace the allowed_paths host paths
        let original = std::fs::read_to_string("tests/fixtures/skip_tools_examples.yaml").unwrap();
        let patched = original
            .replace("\"/tmp\"", &format!("\"{}\"", p("tmp")))
            .replace(
                "\"/var/log:/plugin/logs\"",
                &format!("\"{}:/plugin/logs\"", p("var/log")),
            )
            .replace(
                "\"/home/user/data\"",
                &format!("\"{}\"", p("home/user/data")),
            );

        let mut tmp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        tmp_file.write_all(patched.as_bytes()).unwrap();
        tmp_file.flush().unwrap();

        let cli = Cli {
            config_file: Some(tmp_file.path().to_path_buf()),
            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Failed to load skip_tools examples config: {:?}",
            config_result.err()
        );

        let config = config_result.unwrap();
        assert_eq!(
            config.plugins.len(),
            10,
            "Expected 10 plugins in the config"
        );

        // Test exact_match_plugin
        let exact_plugin = config
            .plugins
            .get(&PluginName::try_from("exact_match_plugin").unwrap())
            .unwrap();
        let exact_skip_tools = exact_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert!(exact_skip_tools.is_match("debug_tool"));
        assert!(exact_skip_tools.is_match("test_runner"));
        assert!(exact_skip_tools.is_match("deprecated_helper"));
        assert!(!exact_skip_tools.is_match("other_tool"));
        assert!(!exact_skip_tools.is_match("debug_tool_extended"));

        // Test wildcard_plugin
        let wildcard_plugin = config
            .plugins
            .get(&PluginName::try_from("wildcard_plugin").unwrap())
            .unwrap();
        let wildcard_skip_tools = wildcard_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert!(wildcard_skip_tools.is_match("temp_file"));
        assert!(wildcard_skip_tools.is_match("temp_data"));
        assert!(wildcard_skip_tools.is_match("file_backup"));
        assert!(wildcard_skip_tools.is_match("data_backup"));
        assert!(wildcard_skip_tools.is_match("debug"));
        assert!(wildcard_skip_tools.is_match("debugger"));
        assert!(!wildcard_skip_tools.is_match("backup_file"));
        assert!(!wildcard_skip_tools.is_match("temp"));

        // Test regex_plugin
        let regex_plugin = config
            .plugins
            .get(&PluginName::try_from("regex_plugin").unwrap())
            .unwrap();
        let regex_skip_tools = regex_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert!(regex_skip_tools.is_match("tool_1"));
        assert!(regex_skip_tools.is_match("tool_42"));
        assert!(regex_skip_tools.is_match("test_unit"));
        assert!(regex_skip_tools.is_match("test_integration"));
        assert!(regex_skip_tools.is_match("data_helper"));
        assert!(!regex_skip_tools.is_match("tool_abc"));
        assert!(!regex_skip_tools.is_match("test_system"));
        assert!(!regex_skip_tools.is_match("Data_helper"));

        // Test anchored_plugin
        let anchored_plugin = config
            .plugins
            .get(&PluginName::try_from("anchored_plugin").unwrap())
            .unwrap();
        let anchored_skip_tools = anchored_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert!(anchored_skip_tools.is_match("system_tool"));
        assert!(anchored_skip_tools.is_match("data_internal"));
        assert!(anchored_skip_tools.is_match("exact_only"));
        assert!(!anchored_skip_tools.is_match("my_system_tool"));
        assert!(!anchored_skip_tools.is_match("data_internal_ext"));
        assert!(!anchored_skip_tools.is_match("exact_only_more"));

        // Test case_sensitive_plugin
        let case_plugin = config
            .plugins
            .get(&PluginName::try_from("case_sensitive_plugin").unwrap())
            .unwrap();
        let case_skip_tools = case_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert!(case_skip_tools.is_match("Tool"));
        assert!(!case_skip_tools.is_match("tool"));
        assert!(!case_skip_tools.is_match("TOOL"));
        assert!(case_skip_tools.is_match("DEBUG_info"));
        assert!(!case_skip_tools.is_match("debug_info"));
        assert!(case_skip_tools.is_match("CamelCaseHelper"));
        assert!(!case_skip_tools.is_match("camelCaseHelper"));

        // Test special_chars_plugin
        let special_plugin = config
            .plugins
            .get(&PluginName::try_from("special_chars_plugin").unwrap())
            .unwrap();
        let special_skip_tools = special_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert!(special_skip_tools.is_match("file.exe"));
        assert!(special_skip_tools.is_match("script?"));
        assert!(special_skip_tools.is_match("temp*data"));
        assert!(special_skip_tools.is_match("path\\tool"));
        assert!(!special_skip_tools.is_match("fileXexe"));
        assert!(!special_skip_tools.is_match("script"));

        // Test empty_skip_plugin
        let empty_plugin = config
            .plugins
            .get(&PluginName::try_from("empty_skip_plugin").unwrap())
            .unwrap();
        let empty_skip_tools = empty_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .skip_tools
            .as_ref()
            .unwrap();
        assert_eq!(empty_skip_tools.len(), 0);
        assert!(!empty_skip_tools.is_match("anything"));

        // Test no_skip_plugin
        let no_skip_plugin = config
            .plugins
            .get(&PluginName::try_from("no_skip_plugin").unwrap())
            .unwrap();
        assert!(
            no_skip_plugin
                .runtime_config
                .as_ref()
                .unwrap()
                .skip_tools
                .is_none()
        );

        // Test full_config_plugin has all components
        let full_plugin = config
            .plugins
            .get(&PluginName::try_from("full_config_plugin").unwrap())
            .unwrap();
        let full_runtime = full_plugin.runtime_config.as_ref().unwrap();
        let full_skip_tools = full_runtime.skip_tools.as_ref().unwrap();
        assert!(full_skip_tools.is_match("admin_tool"));
        assert!(full_skip_tools.is_match("tool_dangerous"));
        assert!(full_skip_tools.is_match("system_critical"));
        assert!(!full_skip_tools.is_match("safe_tool"));
        assert_eq!(full_runtime.allowed_hosts.as_ref().unwrap().len(), 2);
        assert_eq!(full_runtime.allowed_paths.as_ref().unwrap().len(), 3);

        // Verify allowed_paths structure
        let full_allowed_paths = full_runtime.allowed_paths.as_ref().unwrap();
        assert_eq!(full_allowed_paths[0].host.as_str(), p("tmp"));
        assert_eq!(full_allowed_paths[0].plugin.as_str(), p("tmp"));

        #[cfg(not(windows))]
        {
            assert_eq!(full_allowed_paths[1].host.as_str(), p("var/log"));
            assert_eq!(full_allowed_paths[1].plugin.as_str(), "/plugin/logs");
        }

        assert_eq!(full_allowed_paths[2].host.as_str(), p("home/user/data"));
        assert_eq!(full_allowed_paths[2].plugin.as_str(), p("home/user/data"));

        assert_eq!(full_runtime.env_vars.as_ref().unwrap().len(), 2);
        assert_eq!(
            *full_runtime.memory_limit.as_ref().unwrap(),
            ByteSize::gb(2)
        );
    }

    #[test]
    fn test_allowed_path_single_path() {
        // Test deserialization of a single path (same for host and plugin)
        let json = r#""/tmp""#;
        let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

        assert_eq!(allowed_path.host.as_str(), "/tmp");
        assert_eq!(allowed_path.plugin.as_str(), "/tmp");
    }

    #[test]
    fn test_allowed_path_mapped_paths_unix() {
        // Test deserialization with host:plugin mapping on Unix
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host = dir.path().to_str().unwrap();
            let json = format!(r#""{}:/plugin/path""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(allowed_path.plugin.as_str(), "/plugin/path");
        }
    }

    #[test]
    fn test_allowed_path_mapped_paths_windows() {
        // Test deserialization with host;plugin mapping on Windows
        #[cfg(windows)]
        {
            let json = r#""C:\\host\\path;C:\\plugin\\path""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "C:\\host\\path");
            assert_eq!(allowed_path.plugin.as_str(), "C:\\plugin\\path");
        }
    }

    #[test]
    fn test_allowed_path_with_whitespace() {
        // Test that whitespace is trimmed around paths
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host = dir.path().to_str().unwrap();
            let json = format!(r#""  {}  :  /plugin/path  ""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(allowed_path.plugin.as_str(), "/plugin/path");
        }
    }

    #[test]
    fn test_allowed_path_empty_plugin_path() {
        // Test that empty plugin path after separator uses host path
        #[cfg(not(windows))]
        {
            let json = r#""/tmp:""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "/tmp");
            assert_eq!(allowed_path.plugin.as_str(), "/tmp");
        }
    }

    #[test]
    fn test_allowed_path_serialization_single() {
        // Test serialization of a single path
        let allowed_path = AllowedPath {
            host: Utf8PathBuf::from("/tmp"),
            plugin: Utf8PathBuf::from("/tmp"),
        };

        let serialized = serde_json::to_string(&allowed_path).unwrap();
        assert_eq!(serialized, r#""/tmp""#);
    }

    #[test]
    fn test_allowed_path_serialization_mapped_unix() {
        // Test serialization with different host and plugin paths on Unix
        #[cfg(not(windows))]
        {
            let allowed_path = AllowedPath {
                host: Utf8PathBuf::from("/host/path"),
                plugin: Utf8PathBuf::from("/plugin/path"),
            };

            let serialized = serde_json::to_string(&allowed_path).unwrap();
            assert_eq!(serialized, r#""/host/path:/plugin/path""#);
        }
    }

    #[test]
    fn test_allowed_path_serialization_mapped_windows() {
        // Test serialization with different host and plugin paths on Windows
        #[cfg(windows)]
        {
            let allowed_path = AllowedPath {
                host: Utf8PathBuf::from("C:\\host\\path"),
                plugin: Utf8PathBuf::from("C:\\plugin\\path"),
            };

            let serialized = serde_json::to_string(&allowed_path).unwrap();
            assert_eq!(serialized, r#""C:\host\path;C:\plugin\path""#);
        }
    }

    #[test]
    fn test_allowed_path_roundtrip_single() {
        // Test that serialization and deserialization round-trip correctly for single path
        let original = AllowedPath {
            host: Utf8PathBuf::from("/tmp"),
            plugin: Utf8PathBuf::from("/tmp"),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: AllowedPath = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original.host, deserialized.host);
        assert_eq!(original.plugin, deserialized.plugin);
    }

    #[test]
    fn test_allowed_path_roundtrip_mapped() {
        // Test that serialization and deserialization round-trip correctly for mapped paths
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host = dir.path().to_str().unwrap();
            let original = AllowedPath {
                host: Utf8PathBuf::from(host),
                plugin: Utf8PathBuf::from("/plugin/path"),
            };

            let serialized = serde_json::to_string(&original).unwrap();
            let deserialized: AllowedPath = serde_json::from_str(&serialized).unwrap();

            assert_eq!(original.host, deserialized.host);
            assert_eq!(original.plugin, deserialized.plugin);
        }
    }

    #[test]
    fn test_allowed_path_in_runtime_config_yaml() {
        // Test allowed_paths in RuntimeConfig via YAML
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let dir3 = TempDir::new().unwrap();
        let host1 = dir1.path().to_str().unwrap();
        let host2 = dir2.path().to_str().unwrap();
        let host3 = dir3.path().to_str().unwrap();
        let yaml = format!(
            "allowed_paths:\n  - \"{}\"\n  - \"{}:/plugin/logs\"\n  - \"{}\"",
            host1, host2, host3
        );

        let runtime_config: RuntimeConfig = serde_yaml::from_str(&yaml).unwrap();
        let allowed_paths = runtime_config.allowed_paths.unwrap();

        assert_eq!(allowed_paths.len(), 3);
        assert_eq!(allowed_paths[0].host.as_str(), host1);
        assert_eq!(allowed_paths[0].plugin.as_str(), host1);

        #[cfg(not(windows))]
        {
            assert_eq!(allowed_paths[1].host.as_str(), host2);
            assert_eq!(allowed_paths[1].plugin.as_str(), "/plugin/logs");
        }

        assert_eq!(allowed_paths[2].host.as_str(), host3);
        assert_eq!(allowed_paths[2].plugin.as_str(), host3);
    }

    #[test]
    fn test_allowed_path_in_runtime_config_json() {
        // Test allowed_paths in RuntimeConfig via JSON
        let json = r#"
{
  "allowed_paths": [
    "/tmp",
    "/var/log:/plugin/logs"
  ]
}
"#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let allowed_paths = runtime_config.allowed_paths.unwrap();

        assert_eq!(allowed_paths.len(), 2);
        assert_eq!(allowed_paths[0].host.as_str(), "/tmp");
        assert_eq!(allowed_paths[0].plugin.as_str(), "/tmp");

        #[cfg(not(windows))]
        {
            assert_eq!(allowed_paths[1].host.as_str(), "/var/log");
            assert_eq!(allowed_paths[1].plugin.as_str(), "/plugin/logs");
        }
    }

    #[test]
    fn test_allowed_path_multiple_colons() {
        // Test that only the first separator is used (for paths containing colons)
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host = dir.path().to_str().unwrap();
            let json = format!(r#""{}:/plugin/path:with:colons""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(allowed_path.plugin.as_str(), "/plugin/path:with:colons");
        }
    }

    #[test]
    fn test_allowed_path_relative_paths() {
        // Test that paths work (uses a temp directory so the host path exists)
        let dir = TempDir::new().unwrap();
        let host = dir.path().to_str().unwrap();
        let json = format!(r#""{}""#, host);
        let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

        assert_eq!(allowed_path.host.as_str(), host);
        assert_eq!(allowed_path.plugin.as_str(), host);
    }

    #[test]
    fn test_allowed_path_relative_mapped() {
        // Test mapped paths with mapping (uses a temp directory so the host path exists)
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host = dir.path().to_str().unwrap();
            let json = format!(r#""{}:../plugin/path""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(allowed_path.plugin.as_str(), "../plugin/path");
        }
    }

    #[test]
    fn test_allowed_path_complex_paths() {
        // Test complex paths with special characters (uses a temp directory with spaces)
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host_dir = dir.path().join("path with spaces");
            std::fs::create_dir_all(&host_dir).unwrap();
            let host = host_dir.to_str().unwrap();
            let json = format!(r#""{}:/plugin/path-with_underscores""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(
                allowed_path.plugin.as_str(),
                "/plugin/path-with_underscores"
            );
        }
    }

    #[test]
    fn test_allowed_path_yaml_list() {
        // Test a list of allowed_paths in YAML with various formats (uses temp directories)
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let dir3 = TempDir::new().unwrap();
        let dir4 = TempDir::new().unwrap();
        let host1 = dir1.path().to_str().unwrap();
        let host2 = dir2.path().to_str().unwrap();
        let host3 = dir3.path().to_str().unwrap();
        let host4 = dir4.path().to_str().unwrap();
        let yaml = format!(
            "- \"{}\"\n- \"{}:/plugin/logs\"\n- \"{}\"\n- \"{}:../other/path\"",
            host1, host2, host3, host4
        );

        let allowed_paths: Vec<AllowedPath> = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(allowed_paths.len(), 4);

        assert_eq!(allowed_paths[0].host.as_str(), host1);
        assert_eq!(allowed_paths[0].plugin.as_str(), host1);

        #[cfg(not(windows))]
        {
            assert_eq!(allowed_paths[1].host.as_str(), host2);
            assert_eq!(allowed_paths[1].plugin.as_str(), "/plugin/logs");

            assert_eq!(allowed_paths[3].host.as_str(), host4);
            assert_eq!(allowed_paths[3].plugin.as_str(), "../other/path");
        }
    }

    #[test]
    fn test_allowed_path_windows_drive_letters() {
        // Test Windows-style paths with drive letters
        #[cfg(windows)]
        {
            let json = r#""C:\\Users\\test""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "C:\\Users\\test");
            assert_eq!(allowed_path.plugin.as_str(), "C:\\Users\\test");
        }
    }

    #[test]
    fn test_allowed_path_windows_mapped_drives() {
        // Test Windows-style mapped paths between different drives
        #[cfg(windows)]
        {
            let json = r#""C:\\host\\path;D:\\plugin\\path""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "C:\\host\\path");
            assert_eq!(allowed_path.plugin.as_str(), "D:\\plugin\\path");
        }
    }

    #[test]
    fn test_allowed_path_empty_after_whitespace_trim() {
        // Test that whitespace-only plugin path after separator uses host path
        #[cfg(not(windows))]
        {
            let json = r#""/tmp:   ""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "/tmp");
            assert_eq!(allowed_path.plugin.as_str(), "/tmp");
        }
    }

    #[test]
    fn test_runtime_config_allowed_paths_serialization_roundtrip() {
        // Test that RuntimeConfig with allowed_paths survives serialization roundtrip
        #[cfg(not(windows))]
        {
            let original = RuntimeConfig {
                allowed_paths: Some(vec![
                    AllowedPath {
                        host: Utf8PathBuf::from("/tmp"),
                        plugin: Utf8PathBuf::from("/tmp"),
                    },
                    AllowedPath {
                        host: Utf8PathBuf::from("/var/log"),
                        plugin: Utf8PathBuf::from("/plugin/logs"),
                    },
                ]),

                ..Default::default()
            };

            let serialized = serde_json::to_string(&original).unwrap();
            let deserialized: RuntimeConfig = serde_json::from_str(&serialized).unwrap();

            let original_paths = original.allowed_paths.unwrap();
            let deserialized_paths = deserialized.allowed_paths.unwrap();

            assert_eq!(original_paths.len(), deserialized_paths.len());
            assert_eq!(original_paths[0].host, deserialized_paths[0].host);
            assert_eq!(original_paths[0].plugin, deserialized_paths[0].plugin);
            assert_eq!(original_paths[1].host, deserialized_paths[1].host);
            assert_eq!(original_paths[1].plugin, deserialized_paths[1].plugin);
        }
    }

    #[test]
    fn test_allowed_path_unc_paths_windows() {
        // Test Windows UNC paths (\\server\share format)
        #[cfg(windows)]
        {
            let json = r#""\\\\server\\share""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "\\\\server\\share");
            assert_eq!(allowed_path.plugin.as_str(), "\\\\server\\share");
        }
    }

    #[test]
    fn test_allowed_path_unc_mapped_windows() {
        // Test Windows UNC paths with mapping
        #[cfg(windows)]
        {
            let json = r#""\\\\server\\share;C:\\local\\path""#;
            let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

            assert_eq!(allowed_path.host.as_str(), "\\\\server\\share");
            assert_eq!(allowed_path.plugin.as_str(), "C:\\local\\path");
        }
    }

    #[test]
    fn test_allowed_path_very_long_path() {
        // Test very long paths (creates a deep directory structure inside a temp dir)
        let dir = TempDir::new().unwrap();
        let deep = dir
            .path()
            .join("very/long/path/that/goes/on/and/on/through/many/directories/to/test/path/handling/with/extremely/deep/nesting/levels/in/the/filesystem/hierarchy");
        std::fs::create_dir_all(&deep).unwrap();
        let long_path = deep.to_str().unwrap();
        let json = format!(r#""{}""#, long_path);
        let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

        assert_eq!(allowed_path.host.as_str(), long_path);
        assert_eq!(allowed_path.plugin.as_str(), long_path);
    }

    #[test]
    fn test_allowed_path_very_long_mapped() {
        // Test very long mapped paths (creates a deep directory structure inside a temp dir)
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let deep = dir
                .path()
                .join("very/long/host/path/with/many/directories/and/subdirectories");
            std::fs::create_dir_all(&deep).unwrap();
            let long_host = deep.to_str().unwrap();
            let long_plugin = "/equally/long/plugin/path/with/different/directory/structure";
            let json = format!(r#""{}:{}""#, long_host, long_plugin);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), long_host);
            assert_eq!(allowed_path.plugin.as_str(), long_plugin);
        }
    }

    #[test]
    fn test_allowed_path_root_directory() {
        // Test single root directory
        let json = r#""/""#;
        let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

        assert_eq!(allowed_path.host.as_str(), "/");
        assert_eq!(allowed_path.plugin.as_str(), "/");
    }

    #[test]
    fn test_allowed_path_current_directory() {
        // Test current directory notation
        let json = r#"".""#;
        let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

        assert_eq!(allowed_path.host.as_str(), ".");
        assert_eq!(allowed_path.plugin.as_str(), ".");
    }

    #[test]
    fn test_allowed_path_parent_directory() {
        // Test parent directory notation
        let json = r#""..""#;
        let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

        assert_eq!(allowed_path.host.as_str(), "..");
        assert_eq!(allowed_path.plugin.as_str(), "..");
    }

    #[test]
    fn test_allowed_path_tilde_home() {
        // Test that a single path deserializes with matching host and plugin (uses temp directory)
        let dir = TempDir::new().unwrap();
        let host = dir.path().to_str().unwrap();
        let json = format!(r#""{}""#, host);
        let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

        assert_eq!(allowed_path.host.as_str(), host);
        assert_eq!(allowed_path.plugin.as_str(), host);
    }

    #[test]
    fn test_allowed_path_tilde_mapped() {
        // Test tilde paths with mapping
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host = dir.path().to_str().unwrap();
            let json = format!(r#""{}:~/plugin/path""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(allowed_path.plugin.as_str(), "~/plugin/path");
        }
    }

    #[test]
    fn test_allowed_path_unicode_characters() {
        // Test paths with Unicode characters (creates a temp dir with Unicode subdirectory)
        let dir = TempDir::new().unwrap();
        let unicode_dir = dir.path().join("日本語").join("characters");
        std::fs::create_dir_all(&unicode_dir).unwrap();
        let host = unicode_dir.to_str().unwrap();
        let json = format!(r#""{}""#, host);
        let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

        assert_eq!(allowed_path.host.as_str(), host);
        assert_eq!(allowed_path.plugin.as_str(), host);
    }

    #[test]
    fn test_allowed_path_unicode_mapped() {
        // Test Unicode paths with mapping (creates a temp dir with Unicode subdirectory)
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let unicode_dir = dir.path().join("café").join("münster");
            std::fs::create_dir_all(&unicode_dir).unwrap();
            let host = unicode_dir.to_str().unwrap();
            let json = format!(r#""{}:/plugin/データ""#, host);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host);
            assert_eq!(allowed_path.plugin.as_str(), "/plugin/データ");
        }
    }

    #[test]
    fn test_allowed_path_symlink_notation() {
        // Test paths that might represent symlinks
        let json = r#""/usr/local/bin""#;
        let allowed_path: AllowedPath = serde_json::from_str(json).unwrap();

        assert_eq!(allowed_path.host.as_str(), "/usr/local/bin");
        assert_eq!(allowed_path.plugin.as_str(), "/usr/local/bin");
    }

    #[test]
    fn test_allowed_path_trailing_slash() {
        // Test path with trailing slash (uses a temp directory so the host path exists)
        let dir = TempDir::new().unwrap();
        let host_with_slash = format!("{}/", dir.path().to_str().unwrap());
        let json = format!(r#""{}""#, host_with_slash);
        let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

        assert_eq!(allowed_path.host.as_str(), host_with_slash);
        assert_eq!(allowed_path.plugin.as_str(), host_with_slash);
    }

    #[test]
    fn test_allowed_path_trailing_slash_mapped() {
        // Test mapped paths with trailing slashes (uses a temp directory so the host path exists)
        #[cfg(not(windows))]
        {
            let dir = TempDir::new().unwrap();
            let host_with_slash = format!("{}/", dir.path().to_str().unwrap());
            let json = format!(r#""{}:/plugin/path/""#, host_with_slash);
            let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

            assert_eq!(allowed_path.host.as_str(), host_with_slash);
            assert_eq!(allowed_path.plugin.as_str(), "/plugin/path/");
        }
    }

    #[test]
    fn test_allowed_path_numeric_directories() {
        // Test paths with numeric directory names (creates numeric subdirs inside a temp dir)
        let dir = TempDir::new().unwrap();
        let numeric_dir = dir.path().join("2024").join("01").join("15");
        std::fs::create_dir_all(&numeric_dir).unwrap();
        let host = numeric_dir.to_str().unwrap();
        let json = format!(r#""{}""#, host);
        let allowed_path: AllowedPath = serde_json::from_str(&json).unwrap();

        assert_eq!(allowed_path.host.as_str(), host);
        assert_eq!(allowed_path.plugin.as_str(), host);
    }

    #[test]
    fn test_allowed_paths_examples_integration() {
        use std::io::Write;

        let rt = Runtime::new().unwrap();

        // Create a temp directory tree with all host paths the fixture needs
        let base = TempDir::new().unwrap();
        let b = base.path();

        let host_dirs: &[&str] = &[
            "tmp",
            "var/log",
            "home/user/data",
            "host/tmp",
            "home/user",
            "opt/app",
            "local/data",
            "shared/files",
            "relative/path",
            "host/data",
            "shared",
            "local",
            "path/with spaces",
            "host/path with spaces",
            "my documents",
            "path/with-dashes",
            "path_with_underscores",
            "path.with.dots",
            "path/with-special",
            "very/deeply/nested/path/structure",
            "another/deep/path",
            "a/b/c/d/e/f/g",
            "usr/local/share",
            "etc/config",
            "var/lib/data",
            "home/user/.config",
            "root",
            "home",
            "usr",
            "var",
        ];
        for d in host_dirs {
            std::fs::create_dir_all(b.join(d)).unwrap();
        }

        let p = |suffix: &str| -> String { b.join(suffix).to_str().unwrap().to_string() };

        // Generate the YAML fixture dynamically with real temp paths
        let yaml_content = format!(
            r#"plugins:
  single_paths_plugin:
    url: "file:///path/to/single_plugin"
    runtime_config:
      allowed_paths:
        - "{tmp}"
        - "{var_log}"
        - "{home_user_data}"

  mapped_paths_plugin:
    url: "https://example.com/mapped_plugin"
    runtime_config:
      allowed_paths:
        - "{host_tmp}:/plugin/tmp"
        - "{var_log}:/plugin/logs"
        - "{home_user_data}:/plugin/user/data"

  mixed_paths_plugin:
    url: "http://localhost:3000/mixed_plugin"
    runtime_config:
      allowed_paths:
        - "{tmp}"
        - "{var_log}:/plugin/logs"
        - "{home_user}"
        - "{opt_app}:/plugin/app"

  relative_paths_plugin:
    url: "file:///path/to/relative_plugin"
    runtime_config:
      allowed_paths:
        - "{local_data}"
        - "{shared_files}"
        - "{relative_path}"

  mapped_relative_plugin:
    url: "https://api.example.com/relative_plugin"
    runtime_config:
      allowed_paths:
        - "{host_data}:/plugin/data"
        - "{shared}:/plugin/shared"
        - "{local}:remote"

  paths_with_spaces_plugin:
    url: "file:///path/to/spaces_plugin"
    runtime_config:
      allowed_paths:
        - "{path_with_spaces}"
        - "{host_path_with_spaces}:/plugin/path with spaces"
        - "{my_documents}"

  special_chars_plugin:
    url: "https://example.com/special_plugin"
    runtime_config:
      allowed_paths:
        - "{path_with_dashes}"
        - "{path_with_underscores}"
        - "{path_with_dots}"
        - "{path_with_special}:/plugin/with_underscores"

  empty_paths_plugin:
    url: "file:///path/to/empty_plugin"
    runtime_config:
      allowed_paths: []
      allowed_hosts:
        - "example.com"

  no_paths_plugin:
    url: "https://example.com/no_paths_plugin"
    runtime_config:
      allowed_hosts:
        - "localhost"
      memory_limit: "512MB"

  full_config_plugin:
    url: "https://secure.example.com/full_plugin"
    runtime_config:
      skip_tools:
        - "admin_.*"
        - ".*_dangerous"
      allowed_hosts:
        - "api.example.com"
        - "cdn.example.com"
      allowed_paths:
        - "{tmp}"
        - "{var_log}:/plugin/logs"
        - "{home_user_data}"
        - "{opt_app}:/plugin/app"
      env_vars:
        ENVIRONMENT: "production"
        LOG_LEVEL: "info"
        DATA_DIR: "/var/app/data"
      memory_limit: "4GB"

  nested_paths_plugin:
    url: "file:///path/to/nested_plugin"
    runtime_config:
      allowed_paths:
        - "{deeply_nested}"
        - "{another_deep}:/plugin/deep/path"
        - "{abcdefg}"

  multi_mapping_plugin:
    url: "https://example.com/multi_plugin"
    runtime_config:
      allowed_paths:
        - "{usr_local_share}:/plugin/shared"
        - "{etc_config}:/plugin/config"
        - "{var_lib_data}:/plugin/data"
        - "{home_user_config}:/plugin/user/config"

  root_user_paths_plugin:
    url: "file:///path/to/root_user_plugin"
    runtime_config:
      allowed_paths:
        - "{base_root}"
        - "{root}"
        - "{home}"
        - "{usr}"
        - "{var}:/plugin/var"
"#,
            tmp = p("tmp"),
            var_log = p("var/log"),
            home_user_data = p("home/user/data"),
            host_tmp = p("host/tmp"),
            home_user = p("home/user"),
            opt_app = p("opt/app"),
            local_data = p("local/data"),
            shared_files = p("shared/files"),
            relative_path = p("relative/path"),
            host_data = p("host/data"),
            shared = p("shared"),
            local = p("local"),
            path_with_spaces = p("path/with spaces"),
            host_path_with_spaces = p("host/path with spaces"),
            my_documents = p("my documents"),
            path_with_dashes = p("path/with-dashes"),
            path_with_underscores = p("path_with_underscores"),
            path_with_dots = p("path.with.dots"),
            path_with_special = p("path/with-special"),
            deeply_nested = p("very/deeply/nested/path/structure"),
            another_deep = p("another/deep/path"),
            abcdefg = p("a/b/c/d/e/f/g"),
            usr_local_share = p("usr/local/share"),
            etc_config = p("etc/config"),
            var_lib_data = p("var/lib/data"),
            home_user_config = p("home/user/.config"),
            base_root = b.to_str().unwrap(),
            root = p("root"),
            home = p("home"),
            usr = p("usr"),
            var = p("var"),
        );

        // Write to a temp file with .yaml suffix and load the config from it
        let mut tmp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        tmp_file.write_all(yaml_content.as_bytes()).unwrap();
        tmp_file.flush().unwrap();

        let cli = Cli {
            config_file: Some(tmp_file.path().to_path_buf()),
            ..Default::default()
        };

        let config_result = rt.block_on(Config::load(&cli));
        assert!(
            config_result.is_ok(),
            "Failed to load allowed_paths examples config: {:?}",
            config_result.err()
        );

        let config = config_result.unwrap();
        assert_eq!(
            config.plugins.len(),
            13,
            "Expected 13 plugins in the config"
        );

        // Test single_paths_plugin
        let single_plugin = config
            .plugins
            .get(&PluginName::try_from("single_paths_plugin").unwrap())
            .unwrap();
        let single_paths = single_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(single_paths.len(), 3);
        assert_eq!(single_paths[0].host.as_str(), p("tmp"));
        assert_eq!(single_paths[0].plugin.as_str(), p("tmp"));
        assert_eq!(single_paths[1].host.as_str(), p("var/log"));
        assert_eq!(single_paths[1].plugin.as_str(), p("var/log"));
        assert_eq!(single_paths[2].host.as_str(), p("home/user/data"));
        assert_eq!(single_paths[2].plugin.as_str(), p("home/user/data"));

        // Test mapped_paths_plugin
        let mapped_plugin = config
            .plugins
            .get(&PluginName::try_from("mapped_paths_plugin").unwrap())
            .unwrap();
        let mapped_paths = mapped_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(mapped_paths.len(), 3);

        #[cfg(not(windows))]
        {
            assert_eq!(mapped_paths[0].host.as_str(), p("host/tmp"));
            assert_eq!(mapped_paths[0].plugin.as_str(), "/plugin/tmp");
            assert_eq!(mapped_paths[1].host.as_str(), p("var/log"));
            assert_eq!(mapped_paths[1].plugin.as_str(), "/plugin/logs");
            assert_eq!(mapped_paths[2].host.as_str(), p("home/user/data"));
            assert_eq!(mapped_paths[2].plugin.as_str(), "/plugin/user/data");
        }

        // Test mixed_paths_plugin
        let mixed_plugin = config
            .plugins
            .get(&PluginName::try_from("mixed_paths_plugin").unwrap())
            .unwrap();
        let mixed_paths = mixed_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(mixed_paths.len(), 4);
        assert_eq!(mixed_paths[0].host.as_str(), p("tmp"));
        assert_eq!(mixed_paths[0].plugin.as_str(), p("tmp"));

        #[cfg(not(windows))]
        {
            assert_eq!(mixed_paths[1].host.as_str(), p("var/log"));
            assert_eq!(mixed_paths[1].plugin.as_str(), "/plugin/logs");
            assert_eq!(mixed_paths[3].host.as_str(), p("opt/app"));
            assert_eq!(mixed_paths[3].plugin.as_str(), "/plugin/app");
        }

        assert_eq!(mixed_paths[2].host.as_str(), p("home/user"));
        assert_eq!(mixed_paths[2].plugin.as_str(), p("home/user"));

        // Test relative_paths_plugin
        let relative_plugin = config
            .plugins
            .get(&PluginName::try_from("relative_paths_plugin").unwrap())
            .unwrap();
        let relative_paths = relative_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(relative_paths.len(), 3);
        assert_eq!(relative_paths[0].host.as_str(), p("local/data"));
        assert_eq!(relative_paths[0].plugin.as_str(), p("local/data"));
        assert_eq!(relative_paths[1].host.as_str(), p("shared/files"));
        assert_eq!(relative_paths[1].plugin.as_str(), p("shared/files"));
        assert_eq!(relative_paths[2].host.as_str(), p("relative/path"));
        assert_eq!(relative_paths[2].plugin.as_str(), p("relative/path"));

        // Test mapped_relative_plugin
        let mapped_relative = config
            .plugins
            .get(&PluginName::try_from("mapped_relative_plugin").unwrap())
            .unwrap();
        let mapped_rel_paths = mapped_relative
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(mapped_rel_paths.len(), 3);

        #[cfg(not(windows))]
        {
            assert_eq!(mapped_rel_paths[0].host.as_str(), p("host/data"));
            assert_eq!(mapped_rel_paths[0].plugin.as_str(), "/plugin/data");
            assert_eq!(mapped_rel_paths[1].host.as_str(), p("shared"));
            assert_eq!(mapped_rel_paths[1].plugin.as_str(), "/plugin/shared");
            assert_eq!(mapped_rel_paths[2].host.as_str(), p("local"));
            assert_eq!(mapped_rel_paths[2].plugin.as_str(), "remote");
        }

        // Test paths_with_spaces_plugin
        let spaces_plugin = config
            .plugins
            .get(&PluginName::try_from("paths_with_spaces_plugin").unwrap())
            .unwrap();
        let spaces_paths = spaces_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(spaces_paths.len(), 3);
        assert_eq!(spaces_paths[0].host.as_str(), p("path/with spaces"));
        assert_eq!(spaces_paths[0].plugin.as_str(), p("path/with spaces"));

        #[cfg(not(windows))]
        {
            assert_eq!(spaces_paths[1].host.as_str(), p("host/path with spaces"));
            assert_eq!(spaces_paths[1].plugin.as_str(), "/plugin/path with spaces");
        }

        assert_eq!(spaces_paths[2].host.as_str(), p("my documents"));
        assert_eq!(spaces_paths[2].plugin.as_str(), p("my documents"));

        // Test special_chars_plugin
        let special_plugin = config
            .plugins
            .get(&PluginName::try_from("special_chars_plugin").unwrap())
            .unwrap();
        let special_paths = special_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(special_paths.len(), 4);
        assert_eq!(special_paths[0].host.as_str(), p("path/with-dashes"));
        assert_eq!(special_paths[0].plugin.as_str(), p("path/with-dashes"));
        assert_eq!(special_paths[1].host.as_str(), p("path_with_underscores"));
        assert_eq!(special_paths[1].plugin.as_str(), p("path_with_underscores"));
        assert_eq!(special_paths[2].host.as_str(), p("path.with.dots"));
        assert_eq!(special_paths[2].plugin.as_str(), p("path.with.dots"));

        #[cfg(not(windows))]
        {
            assert_eq!(special_paths[3].host.as_str(), p("path/with-special"));
            assert_eq!(special_paths[3].plugin.as_str(), "/plugin/with_underscores");
        }

        // Test empty_paths_plugin
        let empty_plugin = config
            .plugins
            .get(&PluginName::try_from("empty_paths_plugin").unwrap())
            .unwrap();
        let empty_paths = empty_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(empty_paths.len(), 0);

        // Test no_paths_plugin
        let no_paths_plugin = config
            .plugins
            .get(&PluginName::try_from("no_paths_plugin").unwrap())
            .unwrap();
        assert!(
            no_paths_plugin
                .runtime_config
                .as_ref()
                .unwrap()
                .allowed_paths
                .is_none()
        );

        // Test full_config_plugin has all components
        let full_plugin = config
            .plugins
            .get(&PluginName::try_from("full_config_plugin").unwrap())
            .unwrap();
        let full_runtime = full_plugin.runtime_config.as_ref().unwrap();
        let full_skip_tools = full_runtime.skip_tools.as_ref().unwrap();
        assert!(full_skip_tools.is_match("admin_tool"));
        assert!(full_skip_tools.is_match("tool_dangerous"));
        assert!(!full_skip_tools.is_match("safe_tool"));
        assert_eq!(full_runtime.allowed_hosts.as_ref().unwrap().len(), 2);
        assert_eq!(full_runtime.allowed_paths.as_ref().unwrap().len(), 4);

        let full_paths = full_runtime.allowed_paths.as_ref().unwrap();
        assert_eq!(full_paths[0].host.as_str(), p("tmp"));
        assert_eq!(full_paths[0].plugin.as_str(), p("tmp"));

        #[cfg(not(windows))]
        {
            assert_eq!(full_paths[1].host.as_str(), p("var/log"));
            assert_eq!(full_paths[1].plugin.as_str(), "/plugin/logs");
            assert_eq!(full_paths[3].host.as_str(), p("opt/app"));
            assert_eq!(full_paths[3].plugin.as_str(), "/plugin/app");
        }

        assert_eq!(full_paths[2].host.as_str(), p("home/user/data"));
        assert_eq!(full_paths[2].plugin.as_str(), p("home/user/data"));
        assert_eq!(full_runtime.env_vars.as_ref().unwrap().len(), 3);
        assert_eq!(
            *full_runtime.memory_limit.as_ref().unwrap(),
            ByteSize::gb(4)
        );

        // Test nested_paths_plugin
        let nested_plugin = config
            .plugins
            .get(&PluginName::try_from("nested_paths_plugin").unwrap())
            .unwrap();
        let nested_paths = nested_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(nested_paths.len(), 3);
        assert_eq!(
            nested_paths[0].host.as_str(),
            p("very/deeply/nested/path/structure")
        );
        assert_eq!(
            nested_paths[0].plugin.as_str(),
            p("very/deeply/nested/path/structure")
        );

        #[cfg(not(windows))]
        {
            assert_eq!(nested_paths[1].host.as_str(), p("another/deep/path"));
            assert_eq!(nested_paths[1].plugin.as_str(), "/plugin/deep/path");
        }

        assert_eq!(nested_paths[2].host.as_str(), p("a/b/c/d/e/f/g"));
        assert_eq!(nested_paths[2].plugin.as_str(), p("a/b/c/d/e/f/g"));

        // Test multi_mapping_plugin
        let multi_plugin = config
            .plugins
            .get(&PluginName::try_from("multi_mapping_plugin").unwrap())
            .unwrap();
        let multi_paths = multi_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(multi_paths.len(), 4);

        #[cfg(not(windows))]
        {
            assert_eq!(multi_paths[0].host.as_str(), p("usr/local/share"));
            assert_eq!(multi_paths[0].plugin.as_str(), "/plugin/shared");
            assert_eq!(multi_paths[1].host.as_str(), p("etc/config"));
            assert_eq!(multi_paths[1].plugin.as_str(), "/plugin/config");
            assert_eq!(multi_paths[2].host.as_str(), p("var/lib/data"));
            assert_eq!(multi_paths[2].plugin.as_str(), "/plugin/data");
            assert_eq!(multi_paths[3].host.as_str(), p("home/user/.config"));
            assert_eq!(multi_paths[3].plugin.as_str(), "/plugin/user/config");
        }

        // Test root_user_paths_plugin
        let root_plugin = config
            .plugins
            .get(&PluginName::try_from("root_user_paths_plugin").unwrap())
            .unwrap();
        let root_paths = root_plugin
            .runtime_config
            .as_ref()
            .unwrap()
            .allowed_paths
            .as_ref()
            .unwrap();
        assert_eq!(root_paths.len(), 5);
        assert_eq!(root_paths[0].host.as_str(), b.to_str().unwrap());
        assert_eq!(root_paths[0].plugin.as_str(), b.to_str().unwrap());
        assert_eq!(root_paths[1].host.as_str(), p("root"));
        assert_eq!(root_paths[1].plugin.as_str(), p("root"));
        assert_eq!(root_paths[2].host.as_str(), p("home"));
        assert_eq!(root_paths[2].plugin.as_str(), p("home"));
        assert_eq!(root_paths[3].host.as_str(), p("usr"));
        assert_eq!(root_paths[3].plugin.as_str(), p("usr"));

        #[cfg(not(windows))]
        {
            assert_eq!(root_paths[4].host.as_str(), p("var"));
            assert_eq!(root_paths[4].plugin.as_str(), "/plugin/var");
        }
    }

    #[test]
    fn test_allowed_path_nonexistent_host_errors() {
        // Deserializing a path that does not exist on disk must produce an error
        let json = r#""/no/such/path/exists/here""#;
        let result: std::result::Result<AllowedPath, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Expected error for nonexistent host path");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("does not exist"),
            "Error message should mention the path does not exist, got: {msg}"
        );
    }

    #[test]
    fn test_allowed_secrets_none() {
        // Test RuntimeConfig with no allowed_secrets
        let yaml = r#"
    allowed_hosts:
      - "example.com"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(runtime_config.allowed_secrets.is_none());
    }

    #[test]
    fn test_allowed_secrets_single_entry() {
        // Test allowed_secrets with a single keyring entry
        let yaml = r#"
    allowed_secrets:
      - service: "my-app"
        user: "admin"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].service, "my-app");
        assert_eq!(secrets[0].user, "admin");
    }

    #[test]
    fn test_allowed_secrets_multiple_entries() {
        // Test allowed_secrets with multiple keyring entries
        let yaml = r#"
    allowed_secrets:
      - service: "my-app"
        user: "admin"
      - service: "database"
        user: "db_user"
      - service: "api-service"
        user: "api_key_user"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 3);
        assert_eq!(secrets[0].service, "my-app");
        assert_eq!(secrets[0].user, "admin");
        assert_eq!(secrets[1].service, "database");
        assert_eq!(secrets[1].user, "db_user");
        assert_eq!(secrets[2].service, "api-service");
        assert_eq!(secrets[2].user, "api_key_user");
    }

    #[test]
    fn test_allowed_secrets_json_format() {
        // Test allowed_secrets deserialization from JSON
        let json = r#"
    {
      "allowed_secrets": [
        {
          "service": "my-app",
          "user": "admin"
        },
        {
          "service": "database",
          "user": "db_user"
        }
      ]
    }
    "#;

        let runtime_config: RuntimeConfig = serde_json::from_str(json).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].service, "my-app");
        assert_eq!(secrets[0].user, "admin");
        assert_eq!(secrets[1].service, "database");
        assert_eq!(secrets[1].user, "db_user");
    }

    #[test]
    fn test_allowed_secrets_serialization_roundtrip() {
        // Test that allowed_secrets can be serialized and deserialized correctly
        let original_config = RuntimeConfig {
            skip_prompts: None,
            skip_resource_templates: None,
            skip_resources: None,
            skip_tools: None,
            allowed_hosts: None,
            allowed_paths: None,
            allowed_secrets: Some(vec![
                KeyringEntryId {
                    service: "service1".to_string(),
                    user: "user1".to_string(),
                },
                KeyringEntryId {
                    service: "service2".to_string(),
                    user: "user2".to_string(),
                },
            ]),
            env_vars: None,
            memory_limit: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&original_config).unwrap();
        let deserialized: RuntimeConfig = serde_json::from_str(&json).unwrap();

        let secrets = deserialized.allowed_secrets.unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].service, "service1");
        assert_eq!(secrets[0].user, "user1");
        assert_eq!(secrets[1].service, "service2");
        assert_eq!(secrets[1].user, "user2");
    }

    #[test]
    fn test_allowed_secrets_with_special_characters() {
        // Test allowed_secrets with special characters in service and user names
        let yaml = r#"
    allowed_secrets:
      - service: "my-app.production"
        user: "admin@example.com"
      - service: "service_with_underscore"
        user: "user-with-dash"
      - service: "service/with/slash"
        user: "user.with.dots"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 3);
        assert_eq!(secrets[0].service, "my-app.production");
        assert_eq!(secrets[0].user, "admin@example.com");
        assert_eq!(secrets[1].service, "service_with_underscore");
        assert_eq!(secrets[1].user, "user-with-dash");
        assert_eq!(secrets[2].service, "service/with/slash");
        assert_eq!(secrets[2].user, "user.with.dots");
    }

    #[test]
    fn test_allowed_secrets_empty_list() {
        // Test allowed_secrets with an empty list
        let yaml = r#"
    allowed_secrets: []
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 0);
    }

    #[test]
    fn test_allowed_secrets_with_whitespace() {
        // Test allowed_secrets with whitespace in values
        let yaml = r#"
    allowed_secrets:
      - service: "  my-app  "
        user: "  admin  "
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        // YAML preserves whitespace in quoted strings
        assert_eq!(secrets[0].service, "  my-app  ");
        assert_eq!(secrets[0].user, "  admin  ");
    }

    #[test]
    fn test_allowed_secrets_unicode_values() {
        // Test allowed_secrets with Unicode characters
        let yaml = r#"
    allowed_secrets:
      - service: "应用服务"
        user: "用户名"
      - service: "мой-сервис"
        user: "пользователь"
      - service: "アプリ"
        user: "ユーザー"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 3);
        assert_eq!(secrets[0].service, "应用服务");
        assert_eq!(secrets[0].user, "用户名");
        assert_eq!(secrets[1].service, "мой-сервис");
        assert_eq!(secrets[1].user, "пользователь");
        assert_eq!(secrets[2].service, "アプリ");
        assert_eq!(secrets[2].user, "ユーザー");
    }

    #[test]
    fn test_allowed_secrets_in_full_runtime_config() {
        // Test allowed_secrets as part of a complete RuntimeConfig
        let yaml = r#"
    skip_tools:
      - "dangerous_.*"
    allowed_hosts:
      - "example.com"
      - "api.example.com"
    allowed_paths:
      - "/tmp"
      - "/var/log"
    allowed_secrets:
      - service: "my-app"
        user: "admin"
      - service: "database"
        user: "db_user"
    env_vars:
      KEY1: "value1"
      KEY2: "value2"
    memory_limit: "1GB"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();

        // Verify skip_tools
        assert!(runtime_config.skip_tools.is_some());

        // Verify allowed_hosts
        let hosts = runtime_config.allowed_hosts.unwrap();
        assert_eq!(hosts.len(), 2);

        // Verify allowed_paths
        let paths = runtime_config.allowed_paths.unwrap();
        assert_eq!(paths.len(), 2);

        // Verify allowed_secrets
        let secrets = runtime_config.allowed_secrets.unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].service, "my-app");
        assert_eq!(secrets[0].user, "admin");
        assert_eq!(secrets[1].service, "database");
        assert_eq!(secrets[1].user, "db_user");

        // Verify env_vars
        let env_vars = runtime_config.env_vars.unwrap();
        assert_eq!(env_vars.len(), 2);

        // Verify memory_limit
        assert!(runtime_config.memory_limit.is_some());
    }

    #[test]
    fn test_allowed_secrets_json_serialization_roundtrip() {
        // Test JSON serialization roundtrip specifically
        let original_secrets = vec![
            KeyringEntryId {
                service: "test-service".to_string(),
                user: "test-user".to_string(),
            },
            KeyringEntryId {
                service: "prod-service".to_string(),
                user: "prod-user".to_string(),
            },
        ];

        let config = RuntimeConfig {
            skip_prompts: None,
            skip_resource_templates: None,
            skip_resources: None,
            skip_tools: None,
            allowed_hosts: None,
            allowed_paths: None,
            allowed_secrets: Some(original_secrets),
            env_vars: None,
            memory_limit: None,
        };

        // Serialize to JSON string
        let json_str = serde_json::to_string_pretty(&config).unwrap();

        // Deserialize back
        let deserialized: RuntimeConfig = serde_json::from_str(&json_str).unwrap();
        let secrets = deserialized.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].service, "test-service");
        assert_eq!(secrets[0].user, "test-user");
        assert_eq!(secrets[1].service, "prod-service");
        assert_eq!(secrets[1].user, "prod-user");
    }

    #[test]
    fn test_allowed_secrets_yaml_serialization_roundtrip() {
        // Test YAML serialization roundtrip specifically
        let original_secrets = vec![KeyringEntryId {
            service: "yaml-service".to_string(),
            user: "yaml-user".to_string(),
        }];

        let config = RuntimeConfig {
            skip_prompts: None,
            skip_resource_templates: None,
            skip_resources: None,
            skip_tools: None,
            allowed_hosts: None,
            allowed_paths: None,
            allowed_secrets: Some(original_secrets),
            env_vars: None,
            memory_limit: None,
        };

        // Serialize to YAML string
        let yaml_str = serde_yaml::to_string(&config).unwrap();

        // Deserialize back
        let deserialized: RuntimeConfig = serde_yaml::from_str(&yaml_str).unwrap();
        let secrets = deserialized.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].service, "yaml-service");
        assert_eq!(secrets[0].user, "yaml-user");
    }

    #[test]
    fn test_allowed_secrets_long_values() {
        // Test allowed_secrets with very long service and user names
        let long_service = "a".repeat(500);
        let long_user = "b".repeat(500);

        let yaml = format!(
            r#"
    allowed_secrets:
      - service: "{}"
        user: "{}"
    "#,
            long_service, long_user
        );

        let runtime_config: RuntimeConfig = serde_yaml::from_str(&yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].service, long_service);
        assert_eq!(secrets[0].user, long_user);
    }

    #[test]
    fn test_allowed_secrets_duplicate_entries() {
        // Test that duplicate entries are preserved
        let yaml = r#"
    allowed_secrets:
      - service: "my-app"
        user: "admin"
      - service: "my-app"
        user: "admin"
    "#;

        let runtime_config: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = runtime_config.allowed_secrets.unwrap();

        // Duplicates should be preserved in the list
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].service, secrets[1].service);
        assert_eq!(secrets[0].user, secrets[1].user);
    }

    #[test]
    fn test_keyring_entry_id_clone() {
        // Test that KeyringEntryId can be cloned
        let original = KeyringEntryId {
            service: "test-service".to_string(),
            user: "test-user".to_string(),
        };

        let cloned = original.clone();
        assert_eq!(cloned.service, "test-service");
        assert_eq!(cloned.user, "test-user");
    }

    #[test]
    fn test_keyring_entry_id_debug() {
        // Test Debug implementation for KeyringEntryId
        let entry = KeyringEntryId {
            service: "debug-service".to_string(),
            user: "debug-user".to_string(),
        };

        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("debug-service"));
        assert!(debug_str.contains("debug-user"));
    }
}
