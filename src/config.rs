use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt, path::Path, str::FromStr};
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
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
}
