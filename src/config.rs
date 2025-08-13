use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt, path::Path, str::FromStr};
use url::Url;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct PluginName(String);

#[derive(Clone, Debug)]
pub struct PluginNameParseError;

impl fmt::Display for PluginNameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse plugin name")
    }
}

impl std::error::Error for PluginNameParseError {}

static PLUGIN_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*$").expect("Failed to compile plugin name regex")
});

impl PluginName {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PluginName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PluginName::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for PluginName {
    type Error = PluginNameParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if PLUGIN_NAME_REGEX.is_match(value) {
            Ok(PluginName(value.to_owned()))
        } else {
            Err(PluginNameParseError)
        }
    }
}

impl TryFrom<String> for PluginName {
    type Error = PluginNameParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        PluginName::try_from(value.as_str())
    }
}

impl TryFrom<&String> for PluginName {
    type Error = PluginNameParseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        PluginName::try_from(value.as_str())
    }
}

impl FromStr for PluginName {
    type Err = PluginNameParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PluginName::try_from(s)
    }
}

impl fmt::Display for PluginName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
    Keyring { service: String, user: String },
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
            InternalAuthConfig::Keyring { service, user } => {
                use keyring::Entry;
                use serde::de;

                let entry =
                    Entry::new(service.as_str(), user.as_str()).map_err(de::Error::custom)?;
                let secret = entry.get_secret().map_err(de::Error::custom)?;
                Ok(serde_json::from_slice::<AuthConfig>(secret.as_slice())
                    .map_err(de::Error::custom)?)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub auths: Option<HashMap<Url, AuthConfig>>,
    pub plugins: HashMap<PluginName, PluginConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginConfig {
    #[serde(rename = "url", alias = "path")]
    pub url: Url,
    pub runtime_config: Option<RuntimeConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeConfig {
    // List of tool names to skip loading at runtime.
    pub skip_tools: Option<Vec<String>>,
    pub allowed_hosts: Option<Vec<String>>,
    pub allowed_paths: Option<Vec<String>>,
    pub env_vars: Option<HashMap<String, String>>,
    pub memory_limit: Option<String>,
}

pub async fn load_config(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "Config file not found at: {}. Please create a config file first.",
            path.display()
        ));
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read config file at {}", path.display()))?;

    let config = match ext {
        "json" => serde_json::from_str(&content)?,
        "yaml" | "yml" => serde_yaml::from_str(&content)?,
        "toml" => toml::from_str(&content)?,
        _ => return Err(anyhow::anyhow!("Unsupported config format: {}", ext)),
    };

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_plugin_name_valid() {
        let valid_names = vec![
            "plugin1",
            "plugin-name",
            "plugin_name",
            "PluginName",
            "plugin123",
            "plugin-name_123",
        ];

        for name in valid_names {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Failed to parse valid name: {}",
                name
            );
        }
    }

    #[test]
    fn test_plugin_name_invalid() {
        let invalid_names = vec![
            "plugin name",  // spaces not allowed
            "plugin@name",  // special characters not allowed
            "-pluginname",  // cannot start with hyphen
            "pluginname-",  // cannot end with hyphen
            "_pluginname",  // cannot start with underscore
            "pluginname_",  // cannot end with underscore
            "plugin--name", // consecutive hyphens not allowed
            "plugin__name", // consecutive underscores not allowed
            "",             // empty string
        ];
        for name in invalid_names {
            assert!(
                PluginName::try_from(name).is_err(),
                "Parsed invalid name: {}",
                name
            );
        }
    }

    #[test]
    fn test_plugin_name_display() {
        let name_str = "plugin-name_123";
        let plugin_name = PluginName::try_from(name_str).unwrap();
        assert_eq!(plugin_name.to_string(), name_str);
    }

    #[test]
    fn test_plugin_name_serialize_deserialize() {
        let name_str = "plugin-name_123";
        let plugin_name = PluginName::try_from(name_str).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&plugin_name).unwrap();
        assert_eq!(serialized, format!("\"{}\"", name_str));

        // Deserialize
        let deserialized: PluginName = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, plugin_name);
    }

    #[test]
    fn test_load_valid_yaml_config() {
        let rt = Runtime::new().unwrap();

        // Read the test fixture file
        let path = Path::new("tests/fixtures/valid_config.yaml");

        // Load the config
        let config_result = rt.block_on(load_config(&path));
        assert!(config_result.is_ok(), "Failed to load valid YAML config");

        let config = config_result.unwrap();
        assert_eq!(config.plugins.len(), 3, "Expected 3 plugins in the config");

        // Verify plugin names
        assert!(
            config
                .plugins
                .contains_key(&PluginName("test-plugin".to_string()))
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName("another-plugin".to_string()))
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName("minimal-plugin".to_string()))
        );

        // Verify plugin configs
        let test_plugin = &config.plugins[&PluginName("test-plugin".to_string())];
        assert_eq!(test_plugin.url.to_string(), "file:///path/to/plugin");

        let runtime_config = test_plugin.runtime_config.as_ref().unwrap();
        assert_eq!(runtime_config.skip_tools.as_ref().unwrap().len(), 2);
        assert_eq!(runtime_config.allowed_hosts.as_ref().unwrap().len(), 2);
        assert_eq!(runtime_config.allowed_paths.as_ref().unwrap().len(), 2);
        assert_eq!(runtime_config.env_vars.as_ref().unwrap().len(), 2);
        assert_eq!(runtime_config.memory_limit.as_ref().unwrap(), "1GB");

        // Verify minimal plugin has no runtime config
        let minimal_plugin = &config.plugins[&PluginName("minimal-plugin".to_string())];
        assert!(minimal_plugin.runtime_config.is_none());
    }

    #[test]
    fn test_load_valid_json_config() {
        let rt = Runtime::new().unwrap();

        // Read the test fixture file
        let path = Path::new("tests/fixtures/valid_config.json");

        // Load the config
        let config_result = rt.block_on(load_config(&path));

        assert!(config_result.is_ok(), "Failed to load valid JSON config");

        let config = config_result.unwrap();
        assert_eq!(config.plugins.len(), 3, "Expected 3 plugins in the config");

        // Verify plugin names
        assert!(
            config
                .plugins
                .contains_key(&PluginName("test-plugin".to_string()))
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName("another-plugin".to_string()))
        );
        assert!(
            config
                .plugins
                .contains_key(&PluginName("minimal-plugin".to_string()))
        );

        // Verify env vars
        let test_plugin = &config.plugins[&PluginName("test-plugin".to_string())];
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

        // Load the config
        let config_result = rt.block_on(load_config(&path));
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

        // Load the config
        let config_result = rt.block_on(load_config(&path));
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

        // Load the config
        let config_result = rt.block_on(load_config(&path));
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

        // Load the config
        let config_result = rt.block_on(load_config(nonexistent_path));
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

        // Load the config
        let config_result = rt.block_on(load_config(&path));
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
    "test-plugin": {
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
  test-plugin:
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
    "test-plugin": {
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

        let debug_str = format!("{:?}", auth_config);
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
            InternalAuthConfig::Keyring { service, user } => {
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

        let config_result = rt.block_on(load_config(&path));
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

        let config_result = rt.block_on(load_config(&path));
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
            assert!(auths.contains_key(&url), "Missing auth for {}", url_str);
        }
    }

    #[test]
    fn test_load_invalid_auth_config() {
        let rt = Runtime::new().unwrap();
        let path = Path::new("tests/fixtures/invalid_auth_config.yaml");

        let config_result = rt.block_on(load_config(&path));
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
            "Error should indicate invalid auth configuration: {}",
            error_msg
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
            plugins: HashMap::new(),
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
    "test-plugin": {
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
    "test-plugin": {
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
            InternalAuthConfig::Keyring { service, user } => {
                assert_eq!(service, "test-service");
                assert_eq!(user, "test-user");
            }
            _ => panic!("Expected Keyring auth config"),
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
            InternalAuthConfig::Keyring { service, user } => {
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
    "test-plugin": {
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
  test-plugin:
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
            plugins: HashMap::new(),
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
}
