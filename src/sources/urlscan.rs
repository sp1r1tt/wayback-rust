use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use serde::Deserialize;

#[derive(Deserialize)]
struct SearchRes {
    results: Vec<ResItem>,
}

#[derive(Deserialize)]
struct ResItem {
    page: Page,
}

#[derive(Deserialize)]
struct Page {
    url: String,
}

pub async fn fetch_urlscan_urls(
    client: &reqwest::Client,
    domains: &[String],
    rps: u32,
    concurrency: usize,
    pb: Option<ProgressBar>,
) -> Result<Vec<String>> {
    let apikey = std::env::var("URLSCAN_API_KEY").ok();
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
        let k = apikey.clone();
        tasks.push(async move {
            let mut page = 1usize;
            let mut acc = Vec::new();
            loop {
                let _g = s.acquire().await.unwrap();
                l.until_ready().await;
                let url = format!(
                    "https://urlscan.io/api/v1/search/?q=domain:{}&page={}",
                    dom, page
                );
                let mut req = c.get(&url);
                if let Some(k) = &k {
                    req = req.header("API-Key", k);
                }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if !resp.status().is_success() {
                    break;
                }
                let data: SearchRes = match resp.json().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                for r in data.results {
                    acc.push(r.page.url);
                }
                if let Some(p) = &p {
                    p.inc(1);
                }
                if acc.len() == 0 || page >= 5 {
                    break;
                }
                page += 1;
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
