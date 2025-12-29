use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryFrom, fmt, str::FromStr, sync::LazyLock};

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

static PLUGIN_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9]+(?:[_][A-Za-z0-9]+)*$").expect("Failed to compile plugin name regex")
});

pub static RESERVED_PLUGIN_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("prompts");
    set.insert("resources");
    set.insert("tools");
    set
});

impl PluginName {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_name_valid() {
        let valid_names = vec!["plugin1", "plugin_name", "PluginName", "plugin123"];

        for name in valid_names {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Failed to parse valid name: {name}"
            );
        }
    }

    #[test]
    fn test_plugin_name_invalid_comprehensive() {
        // Test various hyphen scenarios - hyphens are no longer allowed
        let hyphen_cases = vec![
            ("plugin-name", "single hyphen"),
            ("plugin-name-test", "multiple hyphens"),
            ("-plugin", "leading hyphen"),
            ("plugin-", "trailing hyphen"),
            ("--plugin", "leading double hyphen"),
            ("plugin--", "trailing double hyphen"),
            ("plugin--name", "consecutive hyphens"),
            ("plugin-_name", "hyphen before underscore"),
            ("plugin_-name", "hyphen after underscore"),
            ("my-plugin-123", "hyphens with numbers"),
            ("Plugin-Name", "hyphens with capitals"),
        ];

        for (name, description) in hyphen_cases {
            assert!(
                PluginName::try_from(name).is_err(),
                "Should reject plugin name '{name}' ({description})"
            );
        }

        // Test underscore edge cases
        let underscore_cases = vec![
            ("_plugin", "leading underscore"),
            ("plugin_", "trailing underscore"),
            ("__plugin", "leading double underscore"),
            ("plugin__", "trailing double underscore"),
            ("plugin__name", "consecutive underscores"),
            ("_plugin_", "leading and trailing underscores"),
        ];

        for (name, description) in underscore_cases {
            assert!(
                PluginName::try_from(name).is_err(),
                "Should reject plugin name '{name}' ({description})"
            );
        }

        // Test special characters
        let special_char_cases = vec![
            ("plugin@name", "at symbol"),
            ("plugin#name", "hash symbol"),
            ("plugin$name", "dollar sign"),
            ("plugin%name", "percent sign"),
            ("plugin&name", "ampersand"),
            ("plugin*name", "asterisk"),
            ("plugin(name)", "parentheses"),
            ("plugin+name", "plus sign"),
            ("plugin=name", "equals sign"),
            ("plugin[name]", "square brackets"),
            ("plugin{name}", "curly braces"),
            ("plugin|name", "pipe symbol"),
            ("plugin\\name", "backslash"),
            ("plugin:name", "colon"),
            ("plugin;name", "semicolon"),
            ("plugin\"name", "double quote"),
            ("plugin'name", "single quote"),
            ("plugin<name>", "angle brackets"),
            ("plugin,name", "comma"),
            ("plugin.name", "period"),
            ("plugin/name", "forward slash"),
            ("plugin?name", "question mark"),
        ];

        for (name, description) in special_char_cases {
            assert!(
                PluginName::try_from(name).is_err(),
                "Should reject plugin name '{name}' ({description})"
            );
        }

        // Test whitespace cases
        let whitespace_cases = vec![
            ("plugin name", "space in middle"),
            (" plugin", "leading space"),
            ("plugin ", "trailing space"),
            ("  plugin", "leading double space"),
            ("plugin  ", "trailing double space"),
            ("plugin  name", "double space in middle"),
            ("plugin\tname", "tab character"),
            ("plugin\nname", "newline character"),
            ("plugin\rname", "carriage return"),
        ];

        for (name, description) in whitespace_cases {
            assert!(
                PluginName::try_from(name).is_err(),
                "Should reject plugin name '{name}' ({description})"
            );
        }

        // Test empty and minimal cases
        let empty_cases = vec![
            ("", "empty string"),
            ("_", "single underscore"),
            ("-", "single hyphen"),
            ("__", "double underscore"),
            ("--", "double hyphen"),
            ("_-", "underscore-hyphen"),
            ("-_", "hyphen-underscore"),
        ];

        for (name, description) in empty_cases {
            assert!(
                PluginName::try_from(name).is_err(),
                "Should reject plugin name '{name}' ({description})"
            );
        }

        // Test unicode and non-ASCII cases
        let unicode_cases = vec![
            ("plugín", "accented character"),
            ("plügïn", "umlaut characters"),
            ("плагин", "cyrillic characters"),
            ("プラグイン", "japanese characters"),
            ("插件", "chinese characters"),
            ("plugin名前", "mixed ASCII and japanese"),
            ("café-plugin", "accented character with hyphen"),
        ];

        for (name, description) in unicode_cases {
            assert!(
                PluginName::try_from(name).is_err(),
                "Should reject plugin name '{name}' ({description})"
            );
        }
    }

    #[test]
    fn test_plugin_name_valid_comprehensive() {
        // Test basic alphanumeric names
        let basic_cases = vec![
            ("plugin", "simple lowercase"),
            ("Plugin", "simple capitalized"),
            ("PLUGIN", "simple uppercase"),
            ("MyPlugin", "camelCase"),
            ("plugin123", "with numbers"),
            ("123plugin", "starting with numbers"),
            ("p", "single character"),
            ("P", "single uppercase character"),
            ("1", "single number"),
        ];

        for (name, description) in basic_cases {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Should accept valid plugin name '{name}' ({description})"
            );
        }

        // Test names with underscores as separators
        let underscore_cases = vec![
            ("plugin_name", "simple underscore"),
            ("my_plugin", "underscore separator"),
            ("plugin_name_test", "multiple underscores"),
            ("Plugin_Name", "underscore with capitals"),
            ("plugin_123", "underscore with numbers"),
            ("my_plugin_v2", "complex with version"),
            ("a_b", "minimal underscore case"),
            ("test_plugin_name_123", "long with mixed content"),
        ];

        for (name, description) in underscore_cases {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Should accept valid plugin name '{name}' ({description})"
            );
        }

        // Test mixed alphanumeric cases
        let mixed_cases = vec![
            ("plugin1", "letters and single digit"),
            ("plugin123", "letters and multiple digits"),
            ("Plugin1Name", "mixed case with digits"),
            ("myPlugin2", "camelCase with digit"),
            ("testPlugin123", "longer mixed case"),
            ("ABC123", "all caps with numbers"),
            ("plugin1_test2", "mixed with underscore"),
            ("My_Plugin_V123", "complex mixed case"),
        ];

        for (name, description) in mixed_cases {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Should accept valid plugin name '{name}' ({description})"
            );
        }

        // Test longer valid names
        let longer_cases = vec![
            (
                "very_long_plugin_name_that_should_be_valid",
                "very long name",
            ),
            (
                "plugin_with_many_underscores_and_numbers_123",
                "long mixed content",
            ),
            ("MyVeryLongPluginNameThatShouldWork", "long camelCase"),
            ("VERY_LONG_UPPERCASE_PLUGIN_NAME", "long uppercase"),
        ];

        for (name, description) in longer_cases {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Should accept valid plugin name '{name}' ({description})"
            );
        }

        // Test edge cases that should be valid
        let edge_cases = vec![
            ("a1", "minimal valid case"),
            ("1a", "number then letter"),
            ("a_1", "letter underscore number"),
            ("1_a", "number underscore letter"),
        ];

        for (name, description) in edge_cases {
            assert!(
                PluginName::try_from(name).is_ok(),
                "Should accept valid plugin name '{name}' ({description})"
            );
        }
    }

    #[test]
    fn test_plugin_name_display() {
        let name_str = "plugin_name_123";
        let plugin_name = PluginName::try_from(name_str).unwrap();
        assert_eq!(plugin_name.to_string(), name_str);
    }

    #[test]
    fn test_plugin_name_serialize_deserialize() {
        let name_str = "plugin_name_123";
        let plugin_name = PluginName::try_from(name_str).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&plugin_name).unwrap();
        assert_eq!(serialized, format!("\"{name_str}\""));

        // Deserialize
        let deserialized: PluginName = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, plugin_name);
    }
}
