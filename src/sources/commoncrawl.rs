use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
struct CollInfo {
    id: String,
}

pub async fn fetch_commoncrawl_urls(
    client: &reqwest::Client,
    domains: &[String],
    rps: u32,
    concurrency: usize,
    indices: usize,
    pb: Option<ProgressBar>,
) -> Result<Vec<String>> {
    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(rps.max(1)).unwrap(),
    )));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut out = Vec::new();

    let info: Vec<CollInfo> = client
        .get("https://index.commoncrawl.org/collinfo.json")
        .send()
        .await?
        .json()
        .await?;
    let mut ids: Vec<String> = info.into_iter().map(|c| c.id).collect();
    ids.sort();
    let indices = indices.max(1);
    let latest: Vec<String> = ids.into_iter().rev().take(indices).collect();

    let mut tasks = FuturesUnordered::new();
    for d in domains {
        for idx in latest.iter() {
            let endpoint = format!(
                "https://index.commoncrawl.org/{idx}-index?url={}/*&output=json",
                d
            );
            let c = client.clone();
            let l = limiter.clone();
            let s = sem.clone();
            let p = pb.clone();
            tasks.push(async move {
                let _g = s.acquire().await.unwrap();
                l.until_ready().await;
                let resp = match c.get(&endpoint).send().await {
                    Ok(r) => r,
                    Err(_) => {
                        if let Some(p) = &p {
                            p.inc(1);
                        }
                        return Ok(Vec::new());
                    }
                };
                if !resp.status().is_success() {
                    if let Some(p) = &p {
                        p.inc(1);
                    }
                    return Ok(Vec::new());
                }
                let text = match resp.text().await {
                    Ok(t) => t,
                    Err(_) => {
                        if let Some(p) = &p {
                            p.inc(1);
                        }
                        return Ok(Vec::new());
                    }
                };
                let mut urls = Vec::new();
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let v: serde_json::Value =
                        serde_json::from_str(line).unwrap_or(serde_json::Value::Null);
                    if let Some(u) = v.get("url").and_then(|x| x.as_str()) {
                        urls.push(u.to_string());
                    }
                }
                if let Some(p) = p {
                    p.inc(1);
                }
                Ok::<_, anyhow::Error>(urls)
            });
        }
    }
    while let Some(v) = tasks.next().await {
        match v {
            Ok(urls) => out.extend(urls),
            Err(_) => {}
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}
