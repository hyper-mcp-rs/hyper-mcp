use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    sync::LazyLock,
};
use wildmatch::WildMatch;

static COMMON_SCOPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert("plugins");
    set.insert("plugins.tools");
    set.insert("plugins.prompts");
    set.insert("plugins.resources");
    set
});

#[derive(Clone, Debug, Default)]
struct ClientScopes(HashSet<String>);

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
    pub fn from_scope_str(scope_str: &str) -> Self {
        let scopes = scope_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        ClientScopes(scopes)
    }

    pub fn has_scope(&self, scope_components: &Vec<&str>) -> bool {
        if scope_components.is_empty() {
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
        if scope_components.len() >= 3 {
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
        }
        // Handle resource-specific scopes that contain wildcards
        if scope_components.len() == 4
            && scope_components[0] == "plugins"
            && scope_components[2] == "resources"
            && scope_components[3].contains("*")
        {
            let scope_prefix = format!("plugins.{}.resources.", scope_components[1]);
            for client_scope in self.iter() {
                if client_scope.starts_with(&scope_prefix) {
                    match client_scope.strip_prefix(&scope_prefix) {
                        Some(resource) => {
                            // Wildcard matching
                            if WildMatch::new(resource).matches(scope_components[3]) {
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
}
