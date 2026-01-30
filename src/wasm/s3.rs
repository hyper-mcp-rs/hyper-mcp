use crate::wasm::{
    cache::{CacheMeta, cache_dir},
    locks::DOWNLOAD_LOCKS,
};
use anyhow::{Result, anyhow};
use aws_sdk_s3::{Client, error::SdkError};
use aws_smithy_types::date_time::{DateTime, Format};
use percent_encoding::percent_decode_str;
use std::path::PathBuf;
use tokio::{fs, sync::OnceCell};
use url::Url;

static S3_CLIENT: OnceCell<Client> = OnceCell::const_new();

pub async fn load_wasm(url: &Url) -> Result<Vec<u8>> {
    let _guard = DOWNLOAD_LOCKS.lock(url).await;

    load_wasm_from_s3_or_cache(
        S3_CLIENT
            .get_or_init(|| async { Client::new(&aws_config::load_from_env().await) })
            .await,
        url,
    )
    .await
}

async fn load_wasm_from_s3_or_cache(s3_client: &Client, url: &Url) -> Result<Vec<u8>> {
    if url.scheme() != "s3" {
        return Err(anyhow!("Invalid S3 URL (missing s3://): {url}"));
    }

    let mut wasm_path = cache_dir();
    wasm_path.push(url.scheme());
    let bucket = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("S3 URL must have a valid bucket name in the host"))?;
    wasm_path.push(bucket);
    for path_segment in url
        .path_segments()
        .ok_or_else(|| anyhow!("URL cannot be a base"))?
    {
        if !(path_segment.is_empty() || path_segment == "." || path_segment == "..") {
            wasm_path.push(percent_decode_str(path_segment).decode_utf8()?.as_ref() as &str);
        }
    }

    let mut request = s3_client
        .get_object()
        .bucket(bucket)
        .key(url.path().trim_start_matches('/'));

    let mut path_str = wasm_path.to_string_lossy().to_string();
    path_str.push_str(".meta");
    let meta_path = PathBuf::from(path_str);
    let mut meta = if meta_path.exists()
        && let Ok(s) = fs::read_to_string(&meta_path).await
        && let Ok(m) = serde_json::from_str::<CacheMeta>(&s)
    {
        if let Some(etag) = &m.etag {
            request = request.if_none_match(etag);
        }
        if let Some(s) = &m.last_modified
            && let Some(dt) = DateTime::from_str(s, Format::DateTimeWithOffset).ok()
        {
            request = request.if_modified_since(dt);
        }
        m
    } else {
        CacheMeta {
            url: url.as_str().to_string(),

            ..Default::default()
        }
    };
    match request.send().await {
        Ok(response) => match response.body.collect().await {
            Ok(body) => {
                if let Some(parent) = wasm_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                meta.etag = response.e_tag;
                meta.last_modified = match response.last_modified {
                    Some(dt) => dt.fmt(Format::DateTimeWithOffset).ok(),
                    None => None,
                };
                let bytes = &body.into_bytes();
                fs::write(&wasm_path, bytes).await?;
                fs::write(meta_path, serde_json::to_string(&meta)?).await?;
                Ok(bytes.to_vec())
            }
            Err(e) => {
                tracing::error!("Failed to collect S3 object body: {e}");
                Err(anyhow::anyhow!("Failed to collect S3 object body: {e}"))
            }
        },
        Err(SdkError::ServiceError(err)) if err.raw().status().as_u16() == 304 => {
            fs::read(wasm_path).await.map_err(|e| e.into())
        }
        Err(e) => {
            tracing::error!("Failed to get object from S3: {e}");
            Err(anyhow::anyhow!("Failed to get object from S3: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
    use aws_sdk_s3::primitives::ByteStream;
    use aws_smithy_mocks::{mock, mock_client};
    use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::date_time::DateTime;

    #[tokio::test]
    async fn test_load_wasm_success() {
        let test_content = b"test-wasm-content";
        let url = Url::parse("s3://test-bucket/path/to/plugin.wasm").unwrap();

        // Create a mock rule that returns a successful response
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(test_content))
                .e_tag("test-etag-123")
                .last_modified(DateTime::from_secs(1234567890))
                .build()
        });

        // Create a mocked S3 client
        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        // Test the function
        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, test_content);

        // Verify the rule was used
        assert_eq!(get_object_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_load_wasm_with_etag_caching() {
        let test_content = b"cached-wasm-content";
        let url = Url::parse("s3://test-bucket-cache/plugin-cache.wasm").unwrap();

        // Get cache paths
        let mut wasm_path = cache_dir();
        wasm_path.push("s3/test-bucket-cache/plugin-cache.wasm");
        let mut meta_path = wasm_path.clone();
        meta_path.set_extension("wasm.meta");

        // Create cache directory and write cached content
        fs::create_dir_all(wasm_path.parent().unwrap())
            .await
            .unwrap();
        fs::write(&wasm_path, test_content).await.unwrap();

        // Write cache metadata with etag
        let meta = CacheMeta {
            etag: Some("cached-etag-456".to_string()),
            last_modified: Some("1234567890".to_string()),
            url: url.as_str().to_string(),
        };
        fs::write(&meta_path, serde_json::to_string(&meta).unwrap())
            .await
            .unwrap();

        // Mock S3 to return 304 Not Modified
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| {
                // Verify that if-none-match header is sent with the cached etag
                req.if_none_match() == Some("cached-etag-456")
            })
            .then_http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(304).unwrap(),
                    aws_smithy_types::body::SdkBody::empty(),
                )
            });

        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        // Test the function with cache
        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, test_content);

        assert_eq!(get_object_rule.num_calls(), 1);

        // Cleanup
        let _ = fs::remove_file(&wasm_path).await;
        let _ = fs::remove_file(&meta_path).await;
    }

    #[tokio::test]
    async fn test_load_wasm_cache_miss_updates_cache() {
        let new_content = b"new-wasm-content";
        let url = Url::parse("s3://test-bucket-new/new/plugin-new.wasm").unwrap();

        // Get cache paths
        let mut wasm_path = cache_dir();
        wasm_path.push("s3/test-bucket-new/new/plugin-new.wasm");
        let mut meta_path = wasm_path.clone();
        meta_path.set_extension("wasm.meta");

        // Mock S3 to return new content
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(new_content))
                .e_tag("new-etag-789")
                .last_modified(DateTime::from_secs(1234567900))
                .build()
        });

        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, new_content);

        // Verify cache was updated
        assert!(wasm_path.exists());
        assert!(meta_path.exists());

        let cached_content = fs::read(&wasm_path).await.unwrap();
        assert_eq!(cached_content, new_content);

        let cached_meta: CacheMeta =
            serde_json::from_str(&fs::read_to_string(&meta_path).await.unwrap()).unwrap();
        assert_eq!(cached_meta.etag, Some("new-etag-789".to_string()));
        assert_eq!(cached_meta.url, url.as_str());

        assert_eq!(get_object_rule.num_calls(), 1);

        // Cleanup
        let _ = fs::remove_file(&wasm_path).await;
        let _ = fs::remove_file(&meta_path).await;
    }

    #[tokio::test]
    async fn test_load_wasm_invalid_scheme() {
        let url = Url::parse("https://example.com/plugin.wasm").unwrap();
        let s3_client = mock_client!(aws_sdk_s3, []);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid S3 URL (missing s3://)")
        );
    }

    #[tokio::test]
    async fn test_load_wasm_s3_error() {
        let url = Url::parse("s3://test-bucket/nonexistent.wasm").unwrap();

        // Mock S3 to return an error
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_error(|| {
            GetObjectError::NoSuchKey(
                aws_sdk_s3::types::error::NoSuchKey::builder()
                    .message("The specified key does not exist")
                    .build(),
            )
        });

        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to get object from S3")
        );

        assert_eq!(get_object_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_load_wasm_with_last_modified() {
        let test_content = b"test-wasm-with-timestamp";
        let url = Url::parse("s3://test-bucket/timestamped.wasm").unwrap();
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(test_content))
                .last_modified(DateTime::from_secs(1234567890))
                .build()
        });

        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, test_content);

        assert_eq!(get_object_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_load_wasm_url_with_special_characters() {
        let test_content = b"special-chars-content";
        let url = Url::parse("s3://test-bucket/path%20with%20spaces/file%2Bname.wasm").unwrap();

        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| {
                req.bucket() == Some("test-bucket")
                    && req.key() == Some("path%20with%20spaces/file%2Bname.wasm")
            })
            .then_output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(test_content))
                    .build()
            });

        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, test_content);

        assert_eq!(get_object_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_load_wasm_with_if_modified_since() {
        let cached_content = b"old-cached-content";
        let url = Url::parse("s3://test-bucket-modified/modified.wasm").unwrap();

        // Get cache paths
        let mut wasm_path = cache_dir();
        wasm_path.push("s3/test-bucket-modified/modified.wasm");
        let mut meta_path = wasm_path.clone();
        meta_path.set_extension("wasm.meta");

        // Create cache with last_modified
        fs::create_dir_all(wasm_path.parent().unwrap())
            .await
            .unwrap();
        fs::write(&wasm_path, cached_content).await.unwrap();

        // Use DateTimeWithOffset format as that's what the code expects when parsing
        let last_modified_str = "2009-02-13T23:31:30Z";
        let meta = CacheMeta {
            etag: None,
            last_modified: Some(last_modified_str.to_string()),
            url: url.as_str().to_string(),
        };
        fs::write(&meta_path, serde_json::to_string(&meta).unwrap())
            .await
            .unwrap();

        // Mock S3 to return 304 Not Modified when if-modified-since matches
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.if_modified_since().is_some())
            .then_http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(304).unwrap(),
                    aws_smithy_types::body::SdkBody::empty(),
                )
            });

        let s3_client = mock_client!(aws_sdk_s3, [&get_object_rule]);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, cached_content);

        assert_eq!(get_object_rule.num_calls(), 1);

        // Cleanup
        let _ = fs::remove_file(&wasm_path).await;
        let _ = fs::remove_file(&meta_path).await;
    }

    #[tokio::test]
    async fn test_load_wasm_missing_bucket() {
        let url = Url::parse("s3:///path/to/file.wasm").unwrap();
        let s3_client = mock_client!(aws_sdk_s3, []);

        let result = load_wasm_from_s3_or_cache(&s3_client, &url).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("S3 URL must have a valid bucket name")
        );
    }
}
