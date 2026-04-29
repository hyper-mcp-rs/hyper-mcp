//! Environment variable expansion for configuration file content.
//!
//! Supported syntax:
//!
//! | Pattern              | Behaviour                                                       |
//! |----------------------|-----------------------------------------------------------------|
//! | `${VAR}`             | Replaced with the value of `VAR`. Error if unset or empty.      |
//! | `${VAR:-default}`    | Replaced with the value of `VAR`, or `default` if unset/empty.  |
//! | `$${VAR}`            | Escape hatch — produces the literal text `${VAR}`.              |
//! | `$${VAR:-default}`   | Escape hatch — produces the literal text `${VAR:-default}`.     |
//! | `$VAR`               | **Not** expanded (left as-is). Important for regex patterns.    |
//!
//! Variable names must match `[A-Za-z_][A-Za-z0-9_]*`.
//!
//! Nested expansion (e.g. `${VAR:-${OTHER}}`) is **not** supported — the
//! default value is taken literally up to the closing `}`, so the inner
//! `${OTHER}` would be expanded as a separate top-level reference during the
//! normal expansion pass, not as part of the default.

use std::sync::LazyLock;

use anyhow::{Result, bail};
use regex::Regex;

/// Regex that matches `${VAR}` and `${VAR:-default}`.
///
/// Capture groups:
///   1 — variable name (`[A-Za-z_][A-Za-z0-9_]*`)
///   2 — optional default value (everything after `:-` up to the closing `}`)
///
/// The default value capture is *non-greedy on purpose*: we use `[^}]*` so it
/// stops at the first `}`.  This means defaults cannot themselves contain `}`.
static ENV_VAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{(?<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?<default>[^}]*))?\}")
        .expect("Failed to compile env-var expansion regex")
});

/// A placeholder that is astronomically unlikely to appear in real config
/// content.  Used to temporarily mask escaped `$${` sequences.
const ESCAPE_PLACEHOLDER: &str = "\x00__DOLLAR_BRACE__\x00";

/// Expand environment variable references in `input`.
///
/// See the [module-level documentation](self) for the full syntax.
///
/// # Errors
///
/// Returns an error listing **all** undefined variables that were referenced
/// without a default value.
pub(crate) fn expand_env_vars(input: &str) -> Result<String> {
    // 1. Replace escaped `$${` with a placeholder so the regex won't see them.
    let masked = input.replace("$${", ESCAPE_PLACEHOLDER);

    // 2. Walk all matches and expand, collecting errors for missing vars.
    let mut missing: Vec<String> = Vec::new();

    let expanded = ENV_VAR_RE.replace_all(&masked, |caps: &regex::Captures<'_>| {
        let name = &caps["name"];
        let value = std::env::var(name).ok().filter(|v| !v.is_empty());

        match (value, caps.name("default")) {
            (Some(val), _) => val,
            (None, Some(default)) => default.as_str().to_owned(),
            (None, None) => {
                missing.push(name.to_owned());
                // Leave a conspicuous marker so the caller can see what was
                // wrong even if they ignore the error.
                format!("${{{name}}}")
            }
        }
    });

    if !missing.is_empty() {
        missing.sort();
        missing.dedup();
        bail!(
            "undefined environment variable{}: {}",
            if missing.len() == 1 { "" } else { "s" },
            missing.join(", ")
        );
    }

    // 3. Restore escaped sequences: placeholder → `${`
    let result = expanded.replace(ESCAPE_PLACEHOLDER, "${");

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. Basic expansion ──────────────────────────────────────────────

    #[test]
    fn test_basic_expansion() {
        unsafe { std::env::set_var("EXPAND_TEST_1_HOME", "/home/user") };
        let result = expand_env_vars("${EXPAND_TEST_1_HOME}").unwrap();
        assert_eq!(result, "/home/user");
        unsafe { std::env::remove_var("EXPAND_TEST_1_HOME") };
    }

    // ── 2. Default value when var is unset ──────────────────────────────

    #[test]
    fn test_default_value_when_unset() {
        unsafe { std::env::remove_var("EXPAND_TEST_2_MISSING") };
        let result = expand_env_vars("${EXPAND_TEST_2_MISSING:-fallback}").unwrap();
        assert_eq!(result, "fallback");
    }

    // ── 3. Default value when var IS set (should use the var) ───────────

    #[test]
    fn test_default_value_when_set() {
        unsafe { std::env::set_var("EXPAND_TEST_3_SET", "real_value") };
        let result = expand_env_vars("${EXPAND_TEST_3_SET:-fallback}").unwrap();
        assert_eq!(result, "real_value");
        unsafe { std::env::remove_var("EXPAND_TEST_3_SET") };
    }

    // ── 4. Empty variable with default ──────────────────────────────────

    #[test]
    fn test_empty_variable_uses_default() {
        unsafe { std::env::set_var("EXPAND_TEST_4_EMPTY", "") };
        let result = expand_env_vars("${EXPAND_TEST_4_EMPTY:-fallback}").unwrap();
        assert_eq!(result, "fallback");
        unsafe { std::env::remove_var("EXPAND_TEST_4_EMPTY") };
    }

    // ── 5. Escape hatch: $${VAR} → literal ${VAR} ──────────────────────

    #[test]
    fn test_escape_hatch() {
        let result = expand_env_vars("$${SOME_VAR}").unwrap();
        assert_eq!(result, "${SOME_VAR}");
    }

    // ── 6. Escape hatch with default ────────────────────────────────────

    #[test]
    fn test_escape_hatch_with_default() {
        let result = expand_env_vars("$${SOME_VAR:-default_val}").unwrap();
        assert_eq!(result, "${SOME_VAR:-default_val}");
    }

    // ── 7. Bare $VAR is NOT expanded ────────────────────────────────────

    #[test]
    fn test_bare_dollar_not_expanded() {
        unsafe { std::env::set_var("EXPAND_TEST_7_HOME", "/home/user") };
        let result = expand_env_vars("$EXPAND_TEST_7_HOME/path").unwrap();
        assert_eq!(result, "$EXPAND_TEST_7_HOME/path");
        unsafe { std::env::remove_var("EXPAND_TEST_7_HOME") };
    }

    // ── 8. Missing variable error ───────────────────────────────────────

    #[test]
    fn test_missing_variable_error() {
        unsafe { std::env::remove_var("EXPAND_TEST_8_UNDEF") };
        let err = expand_env_vars("${EXPAND_TEST_8_UNDEF}").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("EXPAND_TEST_8_UNDEF"),
            "error should mention the missing var, got: {msg}"
        );
    }

    // ── 9. Multiple variables ───────────────────────────────────────────

    #[test]
    fn test_multiple_variables() {
        unsafe { std::env::set_var("EXPAND_TEST_9_A", "alpha") };
        unsafe { std::env::set_var("EXPAND_TEST_9_B", "beta") };
        let result = expand_env_vars("${EXPAND_TEST_9_A} and ${EXPAND_TEST_9_B}").unwrap();
        assert_eq!(result, "alpha and beta");
        unsafe { std::env::remove_var("EXPAND_TEST_9_A") };
        unsafe { std::env::remove_var("EXPAND_TEST_9_B") };
    }

    // ── 10. Mixed content (e.g. JSON-like) ──────────────────────────────

    #[test]
    fn test_mixed_content() {
        unsafe { std::env::set_var("EXPAND_TEST_10_HOME", "/Users/me") };
        let input = r#""url": "file://${EXPAND_TEST_10_HOME}/plugin.wasm""#;
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, r#""url": "file:///Users/me/plugin.wasm""#);
        unsafe { std::env::remove_var("EXPAND_TEST_10_HOME") };
    }

    // ── 11. No variables — passthrough ──────────────────────────────────

    #[test]
    fn test_no_variables_passthrough() {
        let input = "just a plain string with no dollar signs";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, input);
    }

    // ── 12. Multiple missing variables ──────────────────────────────────

    #[test]
    fn test_multiple_missing_variables() {
        unsafe { std::env::remove_var("EXPAND_TEST_12_X") };
        unsafe { std::env::remove_var("EXPAND_TEST_12_Y") };
        let err = expand_env_vars("${EXPAND_TEST_12_X} and ${EXPAND_TEST_12_Y}").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("EXPAND_TEST_12_X"),
            "error should mention X, got: {msg}"
        );
        assert!(
            msg.contains("EXPAND_TEST_12_Y"),
            "error should mention Y, got: {msg}"
        );
    }

    // ── 13. Adjacent expansions ─────────────────────────────────────────

    #[test]
    fn test_adjacent_expansions() {
        unsafe { std::env::set_var("EXPAND_TEST_13_A", "hello") };
        unsafe { std::env::set_var("EXPAND_TEST_13_B", "world") };
        let result = expand_env_vars("${EXPAND_TEST_13_A}${EXPAND_TEST_13_B}").unwrap();
        assert_eq!(result, "helloworld");
        unsafe { std::env::remove_var("EXPAND_TEST_13_A") };
        unsafe { std::env::remove_var("EXPAND_TEST_13_B") };
    }

    // ── 14. Default with special characters ─────────────────────────────

    #[test]
    fn test_default_with_special_chars() {
        unsafe { std::env::remove_var("EXPAND_TEST_14_URL") };
        let result = expand_env_vars("${EXPAND_TEST_14_URL:-https://example.com}").unwrap();
        assert_eq!(result, "https://example.com");
    }

    // ── 15. Empty default ───────────────────────────────────────────────

    #[test]
    fn test_empty_default() {
        unsafe { std::env::remove_var("EXPAND_TEST_15_EMPTY") };
        let result = expand_env_vars("${EXPAND_TEST_15_EMPTY:-}").unwrap();
        assert_eq!(result, "");
    }

    // ── 16. Nested braces in default (NOT supported as nested expansion) ─

    /// `${VAR:-${OTHER}}` does **not** perform nested expansion.  Because
    /// the default-value capture stops at the first `}`, the default text
    /// is literally `${OTHER` (truncated), and the trailing `}` is left
    /// in the output.  In practice users should avoid this pattern.
    ///
    /// However, when OTHER is set the outer replacement yields `${OTHER`
    /// followed by `}` from the remaining input, and then the *second*
    /// pass of the regex doesn't see a valid `${…}` there because it was
    /// already consumed.  Let's just document what actually happens.
    #[test]
    fn test_nested_braces_not_supported() {
        unsafe { std::env::remove_var("EXPAND_TEST_16_OUTER") };
        unsafe { std::env::set_var("EXPAND_TEST_16_INNER", "inner_val") };

        // When the outer var is unset, `${OUTER:-${INNER}}` is parsed as:
        //   name    = "EXPAND_TEST_16_OUTER"
        //   default = "${EXPAND_TEST_16_INNER"   (up to the first `}`)
        // so the replacement is the default text literally, plus the
        // trailing `}` that was not part of the match.
        let result = expand_env_vars("${EXPAND_TEST_16_OUTER:-${EXPAND_TEST_16_INNER}}").unwrap();
        // The default captures "${EXPAND_TEST_16_INNER" and the remaining "}" is literal.
        assert_eq!(result, "${EXPAND_TEST_16_INNER}");

        unsafe { std::env::remove_var("EXPAND_TEST_16_INNER") };
    }
}
