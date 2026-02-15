use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryFrom, fmt, str::FromStr, sync::LazyLock};
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

#[derive(Clone, Debug)]
pub struct PluginNameReservedError;

impl fmt::Display for PluginNameReservedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plugin name is reserved")
    }
}

impl std::error::Error for PluginNameReservedError {}

#[derive(Clone, Debug)]
pub enum PluginNameError {
    ParseError(PluginNameParseError),
    ReservedError(PluginNameReservedError),
}

impl fmt::Display for PluginNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginNameError::ParseError(e) => write!(f, "{}", e),
            PluginNameError::ReservedError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for PluginNameError {}

impl From<PluginNameParseError> for PluginNameError {
    fn from(err: PluginNameParseError) -> Self {
        PluginNameError::ParseError(err)
    }
}

impl From<PluginNameReservedError> for PluginNameError {
    fn from(err: PluginNameReservedError) -> Self {
        PluginNameError::ReservedError(err)
    }
}

static PLUGIN_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9]+(?:[_][A-Za-z0-9]+)*$").expect("Failed to compile plugin name regex")
});

static RESERVED_PLUGIN_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("hyper_mcp");
    set
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
    type Error = PluginNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if RESERVED_PLUGIN_NAMES.contains(value) {
            Err(PluginNameReservedError.into())
        } else if PLUGIN_NAME_REGEX.is_match(value) {
            Ok(PluginName(value.to_owned()))
        } else {
            Err(PluginNameParseError.into())
        }
    }
}

impl TryFrom<String> for PluginName {
    type Error = PluginNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        PluginName::try_from(value.as_str())
    }
}

impl TryFrom<&String> for PluginName {
    type Error = PluginNameError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        PluginName::try_from(value.as_str())
    }
}

impl FromStr for PluginName {
    type Err = PluginNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PluginName::try_from(s)
    }
}

impl fmt::Display for PluginName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct NamespacedNameParseError;

impl fmt::Display for NamespacedNameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse name")
    }
}

impl std::error::Error for NamespacedNameParseError {}

impl From<PluginNameError> for NamespacedNameParseError {
    fn from(_: PluginNameError) -> Self {
        NamespacedNameParseError
    }
}

pub fn create_namespaced_name(plugin_name: &PluginName, name: &str) -> String {
    format!("{plugin_name}-{name}")
}

pub fn create_namespaced_uri(plugin_name: &PluginName, uri: &str) -> Result<String> {
    let mut uri = Url::parse(uri)?;
    uri.set_path(&format!(
        "{}/{}",
        plugin_name.as_str(),
        uri.path().trim_start_matches('/')
    ));
    Ok(uri.to_string())
}

pub fn parse_namespaced_name(namespaced_name: String) -> Result<(PluginName, String)> {
    if let Some((plugin_name, tool_name)) = namespaced_name.split_once("-") {
        return Ok((PluginName::from_str(plugin_name)?, tool_name.to_string()));
    }
    Err(NamespacedNameParseError.into())
}

pub fn parse_namespaced_uri(namespaced_uri: String) -> Result<(PluginName, String)> {
    let mut uri = Url::parse(namespaced_uri.as_str())?;
    let mut segments = uri
        .path_segments()
        .ok_or(url::ParseError::RelativeUrlWithoutBase)?
        .collect::<Vec<&str>>();
    if segments.is_empty() {
        return Err(NamespacedNameParseError.into());
    }
    let plugin_name = PluginName::from_str(segments.remove(0))?;
    uri.set_path(&segments.join("/"));
    Ok((plugin_name, uri.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tool_name() {
        let plugin_name = PluginName::from_str("example_plugin").unwrap();
        let tool_name = "example_tool";
        let expected = "example_plugin-example_tool";
        assert_eq!(create_namespaced_name(&plugin_name, tool_name), expected);
    }

    #[test]
    fn test_parse_tool_name() {
        let tool_name = "example_plugin-example_tool".to_string();
        let result = parse_namespaced_name(tool_name);
        assert!(result.is_ok());
        let (plugin_name, tool) = result.unwrap();
        assert_eq!(plugin_name.as_str(), "example_plugin");
        assert_eq!(tool, "example_tool");
    }

    #[test]
    fn test_create_tool_name_invalid() {
        let plugin_name = PluginName::from_str("example_plugin").unwrap();
        let tool_name = "invalid-tool";
        let result = create_namespaced_name(&plugin_name, tool_name);
        assert_eq!(result, "example_plugin-invalid-tool");
    }

    #[test]
    fn test_create_namespaced_tool_name_with_special_chars() {
        let plugin_name = PluginName::from_str("test_plugin_123").unwrap();
        let tool_name = "tool_name_with_underscores";
        let result = create_namespaced_name(&plugin_name, tool_name);
        assert_eq!(result, "test_plugin_123-tool_name_with_underscores");
    }

    #[test]
    fn test_create_namespaced_tool_name_empty_tool_name() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "";
        let result = create_namespaced_name(&plugin_name, tool_name);
        assert_eq!(result, "test_plugin-");
    }

    #[test]
    fn test_create_namespaced_tool_name_multiple_hyphens() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "invalid-tool-name";
        let result = create_namespaced_name(&plugin_name, tool_name);
        assert_eq!(result, "test_plugin-invalid-tool-name");
    }

    #[test]
    fn test_parse_namespaced_tool_name_with_special_chars() {
        let tool_name = "plugin_name_123-tool_name_456".to_string();
        let result = parse_namespaced_name(tool_name).unwrap();
        assert_eq!(result.0.as_str(), "plugin_name_123");
        assert_eq!(result.1, "tool_name_456");
    }

    #[test]
    fn test_parse_namespaced_tool_name_no_separator() {
        let tool_name = "invalid_tool_name".to_string();
        let result = parse_namespaced_name(tool_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_namespaced_tool_name_multiple_separators() {
        let tool_name = "plugin-tool-extra".to_string();
        let result = parse_namespaced_name(tool_name).unwrap();
        assert_eq!(result.0.as_str(), "plugin");
        assert_eq!(result.1, "tool-extra");
    }

    #[test]
    fn test_parse_namespaced_tool_name_empty_parts() {
        let tool_name = "-tool".to_string();
        let result = parse_namespaced_name(tool_name);
        // This should still work but with empty plugin name
        if result.is_ok() {
            let (plugin, _) = result.unwrap();
            assert!(plugin.as_str().is_empty());
        }
    }

    #[test]
    fn test_parse_namespaced_tool_name_only_separator() {
        let tool_name = "-".to_string();
        let result = parse_namespaced_name(tool_name);
        // Should result in empty plugin and tool names
        if let Ok((plugin, tool)) = result {
            assert!(plugin.as_str().is_empty());
            assert!(tool.is_empty());
        }
    }

    #[test]
    fn test_parse_namespaced_tool_name_empty_string() {
        let tool_name = "".to_string();
        let result = parse_namespaced_name(tool_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_name_parse_error_display() {
        let error = NamespacedNameParseError;
        assert_eq!(format!("{error}"), "Failed to parse name");
    }

    #[test]
    fn test_tool_name_parse_error_from_plugin_name_error() {
        let plugin_error = PluginNameError::ParseError(PluginNameParseError);
        let tool_error: NamespacedNameParseError = plugin_error.into();
        assert_eq!(format!("{tool_error}"), "Failed to parse name");
    }

    #[test]
    fn test_round_trip_tool_name_operations() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let original_tool = "my_tool";

        let namespaced = create_namespaced_name(&plugin_name, original_tool);
        let (parsed_plugin, parsed_tool) = parse_namespaced_name(namespaced).unwrap();

        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_tool, "my_tool");
    }

    #[test]
    fn test_tool_name_with_unicode() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "тест_工具"; // Cyrillic and Chinese characters

        let result = create_namespaced_name(&plugin_name, tool_name);
        assert_eq!(result, "test_plugin-тест_工具");
    }

    #[test]
    fn test_very_long_tool_names() {
        let plugin_name = PluginName::from_str("plugin").unwrap();
        let very_long_tool = "a".repeat(1000);

        let namespaced = create_namespaced_name(&plugin_name, &very_long_tool);

        let (parsed_plugin, parsed_tool) = parse_namespaced_name(namespaced).unwrap();

        assert_eq!(parsed_plugin.as_str(), "plugin");
        assert_eq!(parsed_tool.len(), 1000);
    }

    #[test]
    fn test_plugin_name_error_conversion() {
        let plugin_error = PluginNameError::ParseError(PluginNameParseError);
        let tool_error: NamespacedNameParseError = plugin_error.into();

        // Test that the error implements standard error traits
        assert!(std::error::Error::source(&tool_error).is_none());
        assert!(!format!("{tool_error}").is_empty());
    }

    #[test]
    fn test_tool_name_with_numbers_and_special_chars() {
        let plugin_name = PluginName::from_str("plugin_123").unwrap();
        let tool_name = "tool_456_test";

        let result = create_namespaced_name(&plugin_name, tool_name);
        assert_eq!(result, "plugin_123-tool_456_test");

        let (parsed_plugin, parsed_tool) = parse_namespaced_name(result).unwrap();
        assert_eq!(parsed_plugin.as_str(), "plugin_123");
        assert_eq!(parsed_tool, "tool_456_test");
    }

    #[test]
    fn test_borrowed_vs_owned_cow_strings() {
        // Test with borrowed string
        let borrowed_result = parse_namespaced_name("plugin-tool".to_string());
        assert!(borrowed_result.is_ok());

        // Test with owned string
        let owned_result = parse_namespaced_name("plugin-tool".to_string());
        assert!(owned_result.is_ok());

        let (plugin1, tool1) = borrowed_result.unwrap();
        let (plugin2, tool2) = owned_result.unwrap();

        assert_eq!(plugin1.as_str(), plugin2.as_str());
        assert_eq!(tool1, tool2);
    }

    #[test]
    fn test_namespaced_tool_format_invariants() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "test_tool";

        let namespaced = create_namespaced_name(&plugin_name, tool_name);

        // Should contain at least one "-" (the separator)
        let hyphen_count = namespaced.matches("-").count();
        assert!(hyphen_count >= 1, "Should contain at least one '-'");

        // Should start with plugin name
        assert!(
            namespaced.starts_with("test_plugin"),
            "Should start with plugin name"
        );

        // Should end with tool name
        assert!(
            namespaced.ends_with("test_tool"),
            "Should end with tool name"
        );

        // Should be in the format "plugin-tool"
        assert_eq!(namespaced, "test_plugin-test_tool");

        // Test parsing works correctly with the first hyphen as separator
        let (parsed_plugin, parsed_tool) = parse_namespaced_name(namespaced).unwrap();
        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_tool, "test_tool");
    }

    // Tests for create_namespaced_uri and parse_namespaced_uri

    #[test]
    fn test_create_namespaced_uri_basic() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com/api/endpoint";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(result, "http://example.com/test_plugin/api/endpoint");
    }

    #[test]
    fn test_create_namespaced_uri_root_path() {
        let plugin_name = PluginName::from_str("my_plugin").unwrap();
        let uri = "http://example.com/";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(result, "http://example.com/my_plugin/");
    }

    #[test]
    fn test_create_namespaced_uri_no_path() {
        let plugin_name = PluginName::from_str("my_plugin").unwrap();
        let uri = "http://example.com";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(result, "http://example.com/my_plugin/");
    }

    #[test]
    fn test_create_namespaced_uri_with_query_string() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com/api/endpoint?key=value&foo=bar";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        // Query string should be preserved
        assert!(result.contains("test_plugin/api/endpoint"));
        assert!(result.contains("key=value"));
        assert!(result.contains("foo=bar"));
    }

    #[test]
    fn test_create_namespaced_uri_with_fragment() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com/api/endpoint#section";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert!(result.contains("test_plugin/api/endpoint"));
        assert!(result.contains("#section"));
    }

    #[test]
    fn test_create_namespaced_uri_with_port() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com:8080/api/endpoint";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(result, "http://example.com:8080/test_plugin/api/endpoint");
    }

    #[test]
    fn test_create_namespaced_uri_https() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "https://secure.example.com/api/endpoint";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(
            result,
            "https://secure.example.com/test_plugin/api/endpoint"
        );
    }

    #[test]
    fn test_create_namespaced_uri_leading_slash_path() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com//api/endpoint";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert!(result.contains("test_plugin"));
    }

    #[test]
    fn test_create_namespaced_uri_deep_path() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com/v1/api/v2/endpoint/deep";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(
            result,
            "http://example.com/test_plugin/v1/api/v2/endpoint/deep"
        );
    }

    #[test]
    fn test_create_namespaced_uri_invalid_url() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "not a valid url";

        let result = create_namespaced_uri(&plugin_name, uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_namespaced_uri_with_underscores_in_plugin_name() {
        let plugin_name = PluginName::from_str("my_test_plugin_123").unwrap();
        let uri = "http://example.com/api";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(result, "http://example.com/my_test_plugin_123/api");
    }

    #[test]
    fn test_parse_namespaced_uri_basic() {
        let namespaced_uri = "http://example.com/test_plugin/api/endpoint".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert_eq!(uri, "http://example.com/api/endpoint");
    }

    #[test]
    fn test_parse_namespaced_uri_root_path() {
        let namespaced_uri = "http://example.com/my_plugin/".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "my_plugin");
        assert_eq!(uri, "http://example.com/");
    }

    #[test]
    fn test_parse_namespaced_uri_with_query_string() {
        let namespaced_uri = "http://example.com/test_plugin/api/endpoint?key=value".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert!(uri.contains("api/endpoint"));
        assert!(uri.contains("key=value"));
    }

    #[test]
    fn test_parse_namespaced_uri_with_fragment() {
        let namespaced_uri = "http://example.com/test_plugin/api/endpoint#section".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert!(uri.contains("api/endpoint"));
        assert!(uri.contains("#section"));
    }

    #[test]
    fn test_parse_namespaced_uri_with_port() {
        let namespaced_uri = "http://example.com:8080/test_plugin/api/endpoint".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert_eq!(uri, "http://example.com:8080/api/endpoint");
    }

    #[test]
    fn test_parse_namespaced_uri_https() {
        let namespaced_uri = "https://secure.example.com/test_plugin/api/endpoint".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert_eq!(uri, "https://secure.example.com/api/endpoint");
    }

    #[test]
    fn test_parse_namespaced_uri_deep_path() {
        let namespaced_uri = "http://example.com/test_plugin/v1/api/v2/endpoint/deep".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert_eq!(uri, "http://example.com/v1/api/v2/endpoint/deep");
    }

    #[test]
    fn test_parse_namespaced_uri_invalid_url() {
        let namespaced_uri = "not a valid url".to_string();

        let result = parse_namespaced_uri(namespaced_uri);
        assert!(result.is_err());
    }

    // PluginName tests
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

    #[test]
    fn test_plugin_name_reserved_hyper_mcp() {
        let result = PluginName::try_from("hyper_mcp");
        assert!(result.is_err(), "Should reject reserved name 'hyper_mcp'");

        match result {
            Err(PluginNameError::ReservedError(_)) => {
                // Expected error type
            }
            _ => panic!("Expected PluginNameError::ReservedError"),
        }
    }

    #[test]
    fn test_plugin_name_reserved_error_display() {
        let result = PluginName::try_from("hyper_mcp");
        assert!(result.is_err());

        let err = result.unwrap_err();
        let error_msg = format!("{}", err);
        assert_eq!(error_msg, "Plugin name is reserved");
    }

    #[test]
    fn test_plugin_name_reserved_vs_similar() {
        // Reserved name should be rejected
        assert!(PluginName::try_from("hyper_mcp").is_err());

        // Similar but not reserved names should be accepted
        assert!(PluginName::try_from("hyper").is_ok());
        assert!(PluginName::try_from("mcp").is_ok());
        assert!(PluginName::try_from("hyper_mcp_plugin").is_ok());
        assert!(PluginName::try_from("my_hyper_mcp").is_ok());
        assert!(PluginName::try_from("HYPER_MCP").is_ok()); // case sensitive
    }

    #[test]
    fn test_plugin_name_reserved_from_str() {
        // Test that FromStr also respects reserved names
        let result = PluginName::from_str("hyper_mcp");
        assert!(result.is_err());

        match result {
            Err(PluginNameError::ReservedError(_)) => {
                // Expected error type
            }
            _ => panic!("Expected PluginNameError::ReservedError from FromStr"),
        }
    }

    #[test]
    fn test_plugin_name_reserved_try_from_string() {
        // Test TryFrom<String>
        let name = String::from("hyper_mcp");
        let result = PluginName::try_from(name);
        assert!(result.is_err());

        match result {
            Err(PluginNameError::ReservedError(_)) => {
                // Expected error type
            }
            _ => panic!("Expected PluginNameError::ReservedError from TryFrom<String>"),
        }
    }

    #[test]
    fn test_plugin_name_reserved_deserialize() {
        // Test that deserialization also respects reserved names
        let json = r#""hyper_mcp""#;
        let result: Result<PluginName, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Deserialization should fail for reserved names"
        );
    }

    #[test]
    fn test_plugin_name_error_variants() {
        // Test ParseError variant
        let parse_error = PluginName::try_from("invalid-name");
        assert!(parse_error.is_err());
        match parse_error {
            Err(PluginNameError::ParseError(_)) => {
                // Expected
            }
            _ => panic!("Expected ParseError for invalid format"),
        }

        // Test ReservedError variant
        let reserved_error = PluginName::try_from("hyper_mcp");
        assert!(reserved_error.is_err());
        match reserved_error {
            Err(PluginNameError::ReservedError(_)) => {
                // Expected
            }
            _ => panic!("Expected ReservedError for reserved name"),
        }
    }

    #[test]
    fn test_parse_namespaced_uri_no_path() {
        let namespaced_uri = "http://example.com".to_string();

        let result = parse_namespaced_uri(namespaced_uri);
        // Should fail because there's no path segment for plugin name
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_namespaced_uri_only_plugin() {
        let namespaced_uri = "http://example.com/test_plugin".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "test_plugin");
        assert_eq!(uri, "http://example.com/");
    }

    #[test]
    fn test_round_trip_uri_operations() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let original_uri = "http://example.com/api/endpoint";

        let namespaced = create_namespaced_uri(&plugin_name, original_uri).unwrap();
        let (parsed_plugin, parsed_uri) = parse_namespaced_uri(namespaced).unwrap();

        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_uri, original_uri);
    }

    #[test]
    fn test_round_trip_uri_with_query_and_fragment() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let original_uri = "http://example.com/api/endpoint?key=value#section";

        let namespaced = create_namespaced_uri(&plugin_name, original_uri).unwrap();
        let (parsed_plugin, parsed_uri) = parse_namespaced_uri(namespaced).unwrap();

        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_uri, original_uri);
    }

    #[test]
    fn test_uri_with_special_characters_in_path() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com/api/resource-123_test";

        let namespaced = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(
            namespaced,
            "http://example.com/test_plugin/api/resource-123_test"
        );

        let (parsed_plugin, parsed_uri) = parse_namespaced_uri(namespaced).unwrap();
        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_uri, uri);
    }

    #[test]
    fn test_create_namespaced_uri_with_empty_path() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let uri = "http://example.com/";

        let result = create_namespaced_uri(&plugin_name, uri).unwrap();
        assert_eq!(result, "http://example.com/test_plugin/");
    }

    #[test]
    fn test_parse_namespaced_uri_with_underscores_in_plugin() {
        let namespaced_uri = "http://example.com/my_test_plugin_123/api/resource".to_string();

        let (plugin_name, uri) = parse_namespaced_uri(namespaced_uri).unwrap();
        assert_eq!(plugin_name.as_str(), "my_test_plugin_123");
        assert_eq!(uri, "http://example.com/api/resource");
    }
}
