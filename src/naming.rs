use crate::config::{PluginName, PluginNameParseError};
use anyhow::Result;
use std::{fmt, str::FromStr};
use url::Url;

#[derive(Debug, Clone)]
pub struct NamespacedNameParseError;

impl fmt::Display for NamespacedNameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse name")
    }
}

impl std::error::Error for NamespacedNameParseError {}

impl From<PluginNameParseError> for NamespacedNameParseError {
    fn from(_: PluginNameParseError) -> Self {
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
        let plugin_error = PluginNameParseError;
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
        let plugin_error = PluginNameParseError;
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
