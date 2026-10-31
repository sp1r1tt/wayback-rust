use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use serde::Deserialize;

#[derive(Deserialize)]
struct DataItem {
    attributes: Attrs,
}

#[derive(Deserialize)]
struct Attrs {
    url: Option<String>,
}

#[derive(Deserialize)]
struct Resp {
    data: Vec<DataItem>,
}

pub async fn fetch_virustotal_urls(
    client: &reqwest::Client,
    domains: &[String],
    rps: u32,
    concurrency: usize,
    pb: Option<ProgressBar>,
) -> Result<Vec<String>> {
    let key = match std::env::var("VT_API_KEY") {
        Ok(k) => k,
        Err(_) => return Ok(Vec::new()),
    };
    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(rps.max(1)).unwrap(),
    )));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut out = Vec::new();
    let mut tasks = FuturesUnordered::new();
    for d in domains {
        let dom = d.clone();
        let c = client.clone();
        let l = limiter.clone();
        let s = sem.clone();
        let p = pb.clone();
        let k = key.clone();
        tasks.push(async move {
            let _g = s.acquire().await.unwrap();
            l.until_ready().await;
            let url = format!(
                "https://www.virustotal.com/api/v3/domains/{}/relationships/urls",
                dom
            );
            let resp = match c.get(&url).header("x-apikey", k).send().await {
                Ok(r) => r,
                Err(_) => return Ok(Vec::new()),
            };
            if !resp.status().is_success() {
                return Ok(Vec::new());
            }
            let data: Resp = match resp.json().await {
                Ok(v) => v,
                Err(_) => return Ok(Vec::new()),
            };
            let mut acc = Vec::new();
            for d in data.data {
                if let Some(u) = d.attributes.url {
                    acc.push(u);
                }
            }
            if let Some(p) = p {
                p.inc(1);
            }
            Ok::<_, anyhow::Error>(acc)
        });
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
