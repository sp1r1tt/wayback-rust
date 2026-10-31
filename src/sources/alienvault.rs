use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use serde::Deserialize;

#[derive(Deserialize)]
struct UrlItem {
    url: String,
}

#[derive(Deserialize)]
struct UrlList {
    url_list: Vec<UrlItem>,
    has_next: bool,
}

fn apex_domain(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.');
    if h.is_empty() {
        return None;
    }
    if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    let parts: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    Some(format!(
        "{}.{}",
        parts[parts.len() - 2],
        parts[parts.len() - 1]
    ))
}

pub async fn fetch_alienvault_urls(
    client: &reqwest::Client,
    domains: &[String],
    rps: u32,
    concurrency: usize,
    pb: Option<ProgressBar>,
) -> Result<Vec<String>> {
    let key = std::env::var("OTX_API_KEY").ok();
    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(rps.max(1)).unwrap(),
    )));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let rate_limited = Arc::new(AtomicUsize::new(0));
    let other_http_errors = Arc::new(AtomicUsize::new(0));
    let mut out = Vec::new();
    let mut tasks = FuturesUnordered::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut query_domains: Vec<String> = Vec::new();
    for d in domains {
        if seen.insert(d.clone()) {
            query_domains.push(d.clone());
        }
        if let Some(apex) = apex_domain(d) {
            if seen.insert(apex.clone()) {
                query_domains.push(apex);
            }
        }
    }

    for qd in query_domains {
        let c = client.clone();
        let l = limiter.clone();
        let s = sem.clone();
        let p = pb.clone();
        let k = key.clone();
        let forbidden = forbidden.clone();
        let rate_limited = rate_limited.clone();
        let other_http_errors = other_http_errors.clone();
        tasks.push(async move {
            let mut page = 1usize;
            let mut acc = Vec::new();
            loop {
                let _g = s.acquire().await.unwrap();
                l.until_ready().await;
                let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list?limit=200&page={}", qd, page);
                let mut req = c.get(&url);
                if let Some(k)=&k { req = req.header("X-OTX-API-KEY", k); }
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if !resp.status().is_success() {
                    if resp.status() == reqwest::StatusCode::FORBIDDEN {
                        forbidden.fetch_add(1, Ordering::Relaxed);
                    } else if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        rate_limited.fetch_add(1, Ordering::Relaxed);
                    } else {
                        other_http_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    break;
                }
                let data: UrlList = match resp.json().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                for i in data.url_list { acc.push(i.url); }
                if let Some(p)=&p { p.inc(1); }
                if !data.has_next || page>10 { break; }
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
    if out.is_empty() {
        let forb = forbidden.load(Ordering::Relaxed);
        let rl = rate_limited.load(Ordering::Relaxed);
        let other = other_http_errors.load(Ordering::Relaxed);
        if forb > 0 && key.is_none() {
            return Err(anyhow!("AlienVault вернул 403. Вероятно требуется OTX_API_KEY (переменная окружения или .env)"));
        }
        if rl > 0 {
            return Err(anyhow!(
                "AlienVault вернул 429 (rate limit). Попробуйте --rps 1 и меньшую конкуренцию"
            ));
        }
        if other > 0 {
            return Err(anyhow!("AlienVault вернул HTTP-ошибки. Попробуйте повторить позже или добавить OTX_API_KEY"));
        }
    }
    Ok(out)
}
