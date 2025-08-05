use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt, path::Path, str::FromStr};
use url::Url;

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct PluginName(String);

#[derive(Debug, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub plugins: HashMap<PluginName, PluginConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginConfig {
    #[serde(rename = "url", alias = "path")]
    pub url: Url,
    pub runtime_config: Option<RuntimeConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
}
