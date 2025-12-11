use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    sync::LazyLock,
};
use wildmatch::WildMatch;

pub static COMMON_SCOPES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("plugins".to_string());
    set.insert("plugins.tools".to_string());
    set.insert("plugins.prompts".to_string());
    set.insert("plugins.resources".to_string());
    set
});

#[derive(Clone, Debug, Default)]
pub struct ClientScopes(HashSet<String>);

impl Deref for ClientScopes {
    type Target = HashSet<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClientScopes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ClientScopes {
    pub fn contains_scope(&self, scope_components: [&str; 4]) -> bool {
        if scope_components.is_empty() || scope_components[0] != "plugins" {
            return false;
        }
        let mut candidate_scope = "".to_string();
        // Check for exact matches
        for scope_component in scope_components {
            if candidate_scope.is_empty() {
                candidate_scope = scope_component.to_string();
            } else {
                candidate_scope = format!("{}.{}", candidate_scope, scope_component);
            }
            if self.contains(&candidate_scope) {
                return true;
            }
        }
        // Handle global tools/prompts/resources scopes
        match scope_components[2] {
            "tools" => {
                if self.contains("plugins.tools") {
                    return true;
                }
            }
            "prompts" => {
                if self.contains("plugins.prompts") {
                    return true;
                }
            }
            "resources" => {
                if self.contains("plugins.resources") {
                    return true;
                }
            }
            _ => {}
        }
        // Handle resource-specific scopes that contain wildcards in client scopes
        if scope_components[2] == "resources" {
            let scope_prefix = format!("plugins.{}.resources.", scope_components[1]);
            let requested_resource = scope_components[3];
            for client_scope in self.iter() {
                if client_scope.starts_with(&scope_prefix) && client_scope.contains('*') {
                    match client_scope.strip_prefix(&scope_prefix) {
                        Some(scope_resource_pattern) => {
                            // Check if the client's scope pattern matches the requested resource
                            if WildMatch::new(scope_resource_pattern).matches(requested_resource) {
                                return true;
                            }
                        }
                        None => {}
                    }
                }
            }
        }
        false
    }

    pub fn from_scope(scope: &str) -> Self {
        ClientScopes(scope.split_whitespace().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_scope_str_single_scope() {
        let scopes = ClientScopes::from_scope("plugins");
        assert!(scopes.contains("plugins"));
        assert_eq!(scopes.len(), 1);
    }

    #[test]
    fn test_from_scope_str_multiple_scopes() {
        let scopes = ClientScopes::from_scope("plugins plugins.tools plugins.prompts");
        assert!(scopes.contains("plugins"));
        assert!(scopes.contains("plugins.tools"));
        assert!(scopes.contains("plugins.prompts"));
        assert_eq!(scopes.len(), 3);
    }

    #[test]
    fn test_from_scope_str_with_extra_whitespace() {
        let scopes = ClientScopes::from_scope("plugins   plugins.tools  plugins.prompts");
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains("plugins"));
        assert!(scopes.contains("plugins.tools"));
        assert!(scopes.contains("plugins.prompts"));
    }

    #[test]
    fn test_from_scope_str_empty_string() {
        let scopes = ClientScopes::from_scope("");
        assert_eq!(scopes.len(), 0);
    }

    #[test]
    fn test_default_creates_empty_scopes() {
        let scopes = ClientScopes::default();
        assert_eq!(scopes.len(), 0);
    }

    #[test]
    fn test_has_scope_non_plugins_prefix() {
        let scopes = ClientScopes::from_scope("admin");
        assert!(!scopes.contains_scope(["admin", "tools", "read", "file.txt"]));
    }

    #[test]
    fn test_has_scope_exact_match_four_components() {
        let scopes = ClientScopes::from_scope("plugins.myapp.tools.read");
        assert!(scopes.contains_scope(["plugins", "myapp", "tools", "read"]));
    }

    #[test]
    fn test_has_scope_no_match() {
        let scopes = ClientScopes::from_scope("plugins.myapp.tools.read");
        assert!(!scopes.contains_scope(["plugins", "otherapp", "tools", "write"]));
    }

    #[test]
    fn test_has_scope_partial_match_not_sufficient() {
        let scopes = ClientScopes::from_scope("plugins.tools");
        // Having "plugins.tools" grants access to any app's tools scope
        assert!(scopes.contains_scope(["plugins", "myapp", "tools", "read"]));
        // But it shouldn't grant access to different resource types
        assert!(!scopes.contains_scope(["plugins", "myapp", "prompts", "read"]));
    }

    #[test]
    fn test_has_scope_global_tools_scope() {
        let scopes = ClientScopes::from_scope("plugins.tools");
        assert!(scopes.contains_scope(["plugins", "myapp", "tools", "read"]));
    }

    #[test]
    fn test_has_scope_global_prompts_scope() {
        let scopes = ClientScopes::from_scope("plugins.prompts");
        assert!(scopes.contains_scope(["plugins", "myapp", "prompts", "use"]));
    }

    #[test]
    fn test_has_scope_global_resources_scope() {
        let scopes = ClientScopes::from_scope("plugins.resources");
        assert!(scopes.contains_scope(["plugins", "myapp", "resources", "file://data"]));
    }

    #[test]
    fn test_has_scope_global_scope_does_not_match_different_type() {
        let scopes = ClientScopes::from_scope("plugins.tools");
        assert!(!scopes.contains_scope(["plugins", "myapp", "prompts", "use"]));
    }

    #[test]
    fn test_has_scope_wildcard_resources_exact_match() {
        let scopes = ClientScopes::from_scope("plugins.myapp.resources.file://home/user/data.txt");
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/user/data.txt"
        ]));
    }

    #[test]
    fn test_has_scope_wildcard_resources_wildcard_file_protocol() {
        let scopes = ClientScopes::from_scope("plugins.myapp.resources.file://*");
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/user/data.txt"
        ]));
        assert!(scopes.contains_scope(["plugins", "myapp", "resources", "file://var/log/app.log"]));
    }

    #[test]
    fn test_has_scope_wildcard_resources_http_protocol() {
        let scopes = ClientScopes::from_scope("plugins.myapp.resources.http://*");
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "http://api.example.com/data"
        ]));
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "http://example.com/file"
        ]));
    }

    #[test]
    fn test_has_scope_wildcard_resources_universal_wildcard() {
        let scopes = ClientScopes::from_scope("plugins.myapp.resources.*");
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/user/data.txt"
        ]));
        assert!(scopes.contains_scope(["plugins", "myapp", "resources", "http://example.com/api"]));
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "custom://protocol/resource"
        ]));
    }

    #[test]
    fn test_has_scope_wildcard_resources_no_match() {
        let scopes = ClientScopes::from_scope("plugins.myapp.resources.file://*");
        assert!(!scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "http://example.com/data"
        ]));
    }

    #[test]
    fn test_has_scope_wildcard_resources_multiple_patterns() {
        let scopes = ClientScopes::from_scope(
            "plugins.myapp.resources.file://* plugins.myapp.resources.http://*",
        );
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/user/data.txt"
        ]));
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "http://api.example.com/data"
        ]));
        assert!(!scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "https://secure.example.com/data"
        ]));
    }

    #[test]
    fn test_has_scope_wildcard_pattern_path_prefix() {
        let scopes = ClientScopes::from_scope("plugins.myapp.resources.file://home/docs/*");
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/docs/readme.md"
        ]));
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/docs/guide/intro.txt"
        ]));
        assert!(!scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/other/file.txt"
        ]));
    }

    #[test]
    fn test_deref() {
        let scopes = ClientScopes::from_scope("plugins.myapp.tools plugins.myapp.prompts");
        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains("plugins.myapp.tools"));
    }

    #[test]
    fn test_deref_mut() {
        let mut scopes = ClientScopes::default();
        scopes.insert("plugins.custom.tools.read".to_string());
        assert!(scopes.contains("plugins.custom.tools.read"));
        assert_eq!(scopes.len(), 1);
    }

    #[test]
    fn test_clone() {
        let scopes1 = ClientScopes::from_scope("plugins.myapp.tools plugins.myapp.prompts");
        let scopes2 = scopes1.clone();
        assert_eq!(scopes1.len(), scopes2.len());
        assert!(scopes2.contains("plugins.myapp.tools"));
        assert!(scopes2.contains("plugins.myapp.prompts"));
    }

    #[test]
    fn test_complex_scenario_all_features() {
        let mut scopes = ClientScopes::from_scope(
            "plugins.tools plugins.myapp.resources.file://* plugins.otherapp.resources.http://*",
        );
        scopes.insert("plugins.custom.tools.read".to_string());

        // Test exact matches
        assert!(scopes.contains_scope(["plugins", "custom", "tools", "read"]));

        // Test global tools scope
        assert!(scopes.contains_scope(["plugins", "anotherapp", "tools", "execute"]));

        // Test file:// wildcard resource matching
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file://home/user/data.json"
        ]));
        assert!(scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "file:///var/data/file.csv"
        ]));

        // Test http:// wildcard resource matching for otherapp
        assert!(scopes.contains_scope([
            "plugins",
            "otherapp",
            "resources",
            "http://api.example.com/data"
        ]));

        // Test denied access - wrong protocol
        assert!(!scopes.contains_scope([
            "plugins",
            "myapp",
            "resources",
            "http://example.com/data"
        ]));

        // Test denied access - wrong app
        assert!(!scopes.contains_scope([
            "plugins",
            "unknownapp",
            "resources",
            "file://home/data.txt"
        ]));

        // Test non-existent global scope
        assert!(!scopes.contains_scope(["plugins", "anotherapp", "prompts", "use"]));
    }
}
