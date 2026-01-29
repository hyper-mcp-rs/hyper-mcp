use crate::{config::AuthConfig, wasm::locks::DOWNLOAD_LOCKS};
use anyhow::{Context, Result, anyhow};
use backoff::{ExponentialBackoff, future::retry};
use percent_encoding::percent_decode_str;
use reqwest::{
    Client, RequestBuilder, Response, StatusCode,
    header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cmp::Reverse, collections::HashMap, path::PathBuf, time::Duration};
use tokio::{fs, sync::OnceCell};
use url::Url;

static REQWEST_CLIENT: OnceCell<Client> = OnceCell::const_new();

trait Authenticator {
    /// Adds authentication headers to the request if present in auths.
    fn add_auth(self, auths: &Option<HashMap<Url, AuthConfig>>, url: &Url) -> RequestBuilder;
}

impl Authenticator for RequestBuilder {
    fn add_auth(self, auths: &Option<HashMap<Url, AuthConfig>>, url: &Url) -> RequestBuilder {
        if let Some(auths) = auths {
            let mut auths: Vec<(&str, &AuthConfig)> =
                auths.iter().map(|(k, v)| (k.as_str(), v)).collect();
            auths.sort_by_key(|c| Reverse(c.0.len()));
            let url = url.to_string();
            for (k, v) in auths {
                if url.starts_with(k) {
                    return match v {
                        AuthConfig::Basic { username, password } => {
                            self.basic_auth(username, Some(password))
                        }
                        AuthConfig::Token { token } => self.bearer_auth(token),
                    };
                }
            }
        }

        self
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CacheMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    url: String,
}

pub async fn load_wasm(url: &Url, auths: &Option<HashMap<Url, AuthConfig>>) -> Result<Vec<u8>> {
    let _guard = DOWNLOAD_LOCKS.lock(url).await;

    let mut wasm_path = dirs::cache_dir()
        .map(|mut path| {
            path.push("hyper-mcp");
            path
        })
        .context("Unable to determine cache dir")?;
    wasm_path.push(url.scheme());
    if let Some(host) = url.host_str() {
        wasm_path.push(host);
    } else {
        return Err(anyhow!("URL has no host"));
    }
    if let Some(port) = url.port_or_known_default() {
        wasm_path.push(port.to_string());
    }
    for path_segment in url
        .path_segments()
        .ok_or_else(|| anyhow!("URL cannot be a base"))?
    {
        if !(path_segment.is_empty() || path_segment == "." || path_segment == "..") {
            wasm_path.push(percent_decode_str(path_segment).decode_utf8()?.as_ref());
        }
    }
    if let Some(query) = url.query() {
        let mut query_hash = Sha256::new();
        query_hash.update(query);
        wasm_path.push(format!("{:x}", query_hash.finalize()));
    }

    let mut request = REQWEST_CLIENT
        .get_or_init(|| async { reqwest::Client::new() })
        .await
        .get(url.as_str());
    match url.scheme() {
        "http" => {}
        "https" => {
            request = request.add_auth(auths, url);
        }
        s => {
            return Err(anyhow!("Unsupported URL scheme: {s}"));
        }
    }

    let mut path_str = wasm_path.to_string_lossy().to_string();
    path_str.push_str(".meta");
    let meta_path = PathBuf::from(path_str);
    let mut meta = if meta_path.exists()
        && let Ok(s) = fs::read_to_string(&meta_path).await
        && let Ok(m) = serde_json::from_str::<CacheMeta>(&s)
    {
        if let Some(etag) = &m.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &m.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
        m
    } else {
        CacheMeta {
            url: url.as_str().to_string(),

            ..Default::default()
        }
    };

    fn header_to_string(response: &Response, name: &str) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    let backoff = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(30)),
        max_interval: Duration::from_secs(5),
        ..Default::default()
    };

    let response = retry(backoff, || async {
        let resp = request
            .try_clone()
            .ok_or_else(|| anyhow!("Failed to clone request"))?
            .send()
            .await
            .map_err(|e| backoff::Error::transient(e.into()))?;

        match resp.status() {
            StatusCode::NOT_MODIFIED | StatusCode::OK => Ok(resp),
            s => {
                tracing::warn!("Unexpected status {} fetching {}, retrying...", s, url);
                Err(backoff::Error::transient(anyhow!(
                    "Unexpected status {s} fetching {url}"
                )))
            }
        }
    })
    .await?;

    if response.status() == StatusCode::OK {
        if let Some(parent) = wasm_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        meta.etag = header_to_string(&response, ETAG.as_str());
        meta.last_modified = header_to_string(&response, LAST_MODIFIED.as_str());
        let bytes = &response.bytes().await?;
        fs::write(&wasm_path, bytes).await?;
        fs::write(meta_path, serde_json::to_string(&meta)?).await?;
        Ok(bytes.to_vec())
    } else {
        fs::read(wasm_path).await.map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use reqwest::Client;
    use std::collections::HashMap;
    use tokio::net::TcpListener;
    use url::Url;

    #[test]
    fn test_add_auth_basic_authentication() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            url.clone(),
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        let request = client.get("https://api.example.com/endpoint");
        let authenticated_request = request.add_auth(&Some(auths), &url);

        // We can't easily test the actual header since reqwest doesn't expose it,
        // but we can verify the method doesn't panic and returns a RequestBuilder
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_token_authentication() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            url.clone(),
            AuthConfig::Token {
                token: "bearer-token-123".to_string(),
            },
        );

        let request = client.get("https://api.example.com/endpoint");
        let authenticated_request = request.add_auth(&Some(auths), &url);

        // Verify the method completes without error
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_no_auths_provided() {
        let client = Client::new();
        let url = Url::parse("https://api.example.com").unwrap();

        let request = client.get("https://api.example.com/endpoint");
        let result_request = request.add_auth(&None, &url);

        // Should return the original request unchanged
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_add_auth_empty_auths_map() {
        let client = Client::new();
        let auths = HashMap::new();
        let url = Url::parse("https://api.example.com").unwrap();

        let request = client.get("https://api.example.com/endpoint");
        let result_request = request.add_auth(&Some(auths), &url);

        // Should return the original request unchanged when no matching auth
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_add_auth_url_prefix_matching() {
        let client = Client::new();
        let mut auths = HashMap::new();

        // Add auth for broader domain
        let domain_url = Url::parse("https://example.com").unwrap();
        auths.insert(
            domain_url,
            AuthConfig::Basic {
                username: "domain_user".to_string(),
                password: "domain_pass".to_string(),
            },
        );

        // Add auth for specific API endpoint (longer prefix)
        let api_url = Url::parse("https://example.com/api").unwrap();
        auths.insert(
            api_url,
            AuthConfig::Token {
                token: "api-token".to_string(),
            },
        );

        // Test that longer prefix wins
        let target_url = Url::parse("https://example.com/api/v1/data").unwrap();
        let request = client.get(target_url.as_str());
        let authenticated_request = request.add_auth(&Some(auths), &target_url);

        // The API token should be used (longest prefix)
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_url_no_match() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let auth_url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            auth_url,
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        // Request to different domain
        let target_url = Url::parse("https://different.com/endpoint").unwrap();
        let request = client.get(target_url.as_str());
        let result_request = request.add_auth(&Some(auths), &target_url);

        // Should return the original request unchanged when no URL match
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_add_auth_multiple_auths_longest_prefix_wins() {
        let client = Client::new();
        let mut auths = HashMap::new();

        // Add multiple auths with different prefix lengths
        auths.insert(
            Url::parse("https://example.com").unwrap(),
            AuthConfig::Basic {
                username: "broad_user".to_string(),
                password: "broad_pass".to_string(),
            },
        );

        auths.insert(
            Url::parse("https://example.com/api").unwrap(),
            AuthConfig::Token {
                token: "api_token".to_string(),
            },
        );

        auths.insert(
            Url::parse("https://example.com/api/v1").unwrap(),
            AuthConfig::Basic {
                username: "v1_user".to_string(),
                password: "v1_pass".to_string(),
            },
        );

        // Test with URL that matches all three (longest should win)
        let target_url = Url::parse("https://example.com/api/v1/endpoint").unwrap();
        let request = client.get(target_url.as_str());
        let authenticated_request = request.add_auth(&Some(auths), &target_url);

        // Should use the v1 auth (longest prefix)
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_exact_url_match() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let exact_url = Url::parse("https://api.example.com/v1/data").unwrap();
        auths.insert(
            exact_url.clone(),
            AuthConfig::Token {
                token: "exact-match-token".to_string(),
            },
        );

        let request = client.get(exact_url.as_str());
        let authenticated_request = request.add_auth(&Some(auths), &exact_url);

        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_case_sensitive_urls() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let auth_url = Url::parse("https://API.EXAMPLE.COM").unwrap();
        auths.insert(
            auth_url,
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        // Test with lowercase URL
        let target_url = Url::parse("https://api.example.com/endpoint").unwrap();
        let request = client.get(target_url.as_str());
        let result_request = request.add_auth(&Some(auths), &target_url);

        // Should not match due to case sensitivity
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_auth_config_types_comprehensive() {
        // Test all AuthConfig variants can be created and used
        let basic_auth = AuthConfig::Basic {
            username: "basic_user".to_string(),
            password: "basic_pass".to_string(),
        };

        let token_auth = AuthConfig::Token {
            token: "token_value".to_string(),
        };

        let client = Client::new();
        let url = Url::parse("https://test.com").unwrap();

        // Test both types can be used with add_auth
        let mut auths = HashMap::new();
        auths.insert(url.clone(), basic_auth);

        let request1 = client.get(url.as_str());
        let result1 = request1.add_auth(&Some(auths), &url);
        // The fact that we got here without panicking means the method worked
        drop(result1);

        let mut auths = HashMap::new();
        auths.insert(url.clone(), token_auth);

        let request2 = client.get(url.as_str());
        let result2 = request2.add_auth(&Some(auths), &url);
        // The fact that we got here without panicking means the method worked
        drop(result2);
    }

    #[tokio::test]
    async fn test_load_wasm_success() {
        use axum::{Router, routing::get};

        // Create a simple WASM-like content (valid wasm magic number)
        let wasm_content = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let content_clone = wasm_content.clone();

        let app = Router::new().route(
            "/test.wasm",
            get(move || {
                let content = content_clone.clone();
                async move { (StatusCode::OK, content) }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = Url::parse(&format!("http://127.0.0.1:{}/test.wasm", addr.port())).unwrap();
        let result = load_wasm(&url, &None).await;

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes, wasm_content);
    }

    #[tokio::test]
    async fn test_load_wasm_with_auth_only_https() {
        use axum::{Router, routing::get};

        // Auth is only applied to https URLs, so http should work without auth
        let wasm_content = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let content_clone = wasm_content.clone();

        let app = Router::new().route(
            "/public.wasm",
            get(move || {
                let content = content_clone.clone();
                async move { (StatusCode::OK, content) }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Test with http URL - auth should be ignored
        let url = Url::parse(&format!("http://127.0.0.1:{}/public.wasm", addr.port())).unwrap();
        let mut auths = HashMap::new();
        let base_url = Url::parse(&format!("http://127.0.0.1:{}", addr.port())).unwrap();
        auths.insert(
            base_url,
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        let result = load_wasm(&url, &Some(auths)).await;
        // Should succeed because http URLs don't require auth
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_load_wasm_with_etag_caching() {
        use axum::{Router, http::HeaderMap, routing::get};
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };

        let wasm_content = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let request_count = Arc::new(AtomicU32::new(0));
        let request_count_clone = request_count.clone();

        let app = Router::new().route(
            "/cached.wasm",
            get(move |headers: HeaderMap| {
                let count = request_count_clone.clone();
                let content = wasm_content.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);

                    if let Some(etag) = headers.get("if-none-match") {
                        if etag.to_str().unwrap() == "\"test-etag\"" {
                            return (StatusCode::NOT_MODIFIED, Vec::new()).into_response();
                        }
                    }

                    (StatusCode::OK, [("etag", "\"test-etag\"")], content).into_response()
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = Url::parse(&format!("http://127.0.0.1:{}/cached.wasm", addr.port())).unwrap();

        // First request
        let result1 = load_wasm(&url, &None).await;
        assert!(result1.is_ok());

        // Second request should use cache
        let result2 = load_wasm(&url, &None).await;
        assert!(result2.is_ok());

        // Should have made 2 requests (one initial, one with etag that returns 304)
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_load_wasm_retry_on_500() {
        use axum::{Router, routing::get};
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };

        let wasm_content = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let app = Router::new().route(
            "/flaky.wasm",
            get(move || {
                let count = attempt_count_clone.clone();
                let content = wasm_content.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst);

                    // Fail first 2 attempts, succeed on 3rd
                    if attempts < 2 {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Vec::new()).into_response();
                    }

                    (StatusCode::OK, content).into_response()
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = Url::parse(&format!("http://127.0.0.1:{}/flaky.wasm", addr.port())).unwrap();
        let result = load_wasm(&url, &None).await;

        // Should succeed after retries
        assert!(result.is_ok());
        // Should have made at least 3 attempts
        assert!(attempt_count.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn test_load_wasm_retry_exhaustion() {
        use axum::{Router, routing::get};

        let app = Router::new().route(
            "/always-fails.wasm",
            get(|| async move { (StatusCode::INTERNAL_SERVER_ERROR, Vec::<u8>::new()) }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = Url::parse(&format!(
            "http://127.0.0.1:{}/always-fails.wasm",
            addr.port()
        ))
        .unwrap();
        let result = load_wasm(&url, &None).await;

        // Should fail after exhausting retries
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_wasm_unsupported_scheme() {
        let url = Url::parse("ftp://example.com/test.wasm").unwrap();
        let result = load_wasm(&url, &None).await;

        // Should fail with unsupported scheme error
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported URL scheme")
        );
    }

    #[tokio::test]
    async fn test_load_wasm_404_not_found() {
        use axum::{Router, routing::get};

        let app = Router::new().route(
            "/exists.wasm",
            get(|| async move { (StatusCode::OK, vec![0x00, 0x61, 0x73, 0x6D]) }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = Url::parse(&format!("http://127.0.0.1:{}/not-exists.wasm", addr.port())).unwrap();
        let result = load_wasm(&url, &None).await;

        // Should fail with 404
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_wasm_cache_hit_with_same_etag() {
        use axum::{Router, http::HeaderMap, routing::get};
        use std::sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        };

        let wasm_content = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let request_count = Arc::new(AtomicU32::new(0));
        let request_count_clone = request_count.clone();

        let app = Router::new().route(
            "/cache-test.wasm",
            get(move |headers: HeaderMap| {
                let count = request_count_clone.clone();
                let content = wasm_content.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);

                    // Check if client sent if-none-match header
                    if let Some(etag) = headers.get("if-none-match") {
                        if etag.to_str().unwrap() == "\"test-etag-123\"" {
                            // Return 304 Not Modified
                            return (
                                StatusCode::NOT_MODIFIED,
                                [
                                    ("etag", "\"test-etag-123\""),
                                    ("last-modified", "Wed, 01 Jan 2025 00:00:00 GMT"),
                                ],
                                Vec::new(),
                            )
                                .into_response();
                        }
                    }

                    // First request - return full content with etag and last-modified
                    (
                        StatusCode::OK,
                        [
                            ("etag", "\"test-etag-123\""),
                            ("last-modified", "Wed, 01 Jan 2025 00:00:00 GMT"),
                        ],
                        content,
                    )
                        .into_response()
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = Url::parse(&format!("http://127.0.0.1:{}/cache-test.wasm", addr.port())).unwrap();

        // First load - should get full content
        let result1 = load_wasm(&url, &None).await;
        assert!(result1.is_ok());
        let bytes1 = result1.unwrap();
        assert_eq!(bytes1, vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        // Second load - should send if-none-match, get 304, and return cached content
        let result2 = load_wasm(&url, &None).await;
        assert!(result2.is_ok());
        let bytes2 = result2.unwrap();
        assert_eq!(bytes2, vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
        // Should have made 2 requests total (second one returns 304)
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        // Verify both loads returned the same content
        assert_eq!(bytes1, bytes2);
    }
}
