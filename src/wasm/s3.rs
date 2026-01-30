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
                    Some(dt) => match dt.fmt(Format::EpochSeconds) {
                        Ok(s) => Some(s),
                        _ => None,
                    },
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
mod tests {}
