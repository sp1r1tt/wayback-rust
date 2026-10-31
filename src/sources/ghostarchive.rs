use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use url::{form_urlencoded, Url};

fn normalize_domain(input: &str) -> String {
    let mut s = input.trim().to_string();
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host.to_string();
    }
    s.trim_end_matches('.').to_string()
}

fn host_matches_domain(u: &Url, domain: &str) -> bool {
    let Some(host) = u.host_str() else {
        return false;
    };
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn extract_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let hay = text.as_bytes();
    let mut i = 0usize;
    while i < hay.len() {
        let start = if hay[i..].starts_with(b"https://") {
            Some(i)
        } else if hay[i..].starts_with(b"http://") {
            Some(i)
        } else {
            None
        };
        let Some(s) = start else {
            i += 1;
            continue;
        };
        let mut j = s;
        while j < hay.len() {
            let c = hay[j];
            if c.is_ascii_whitespace() || c == b'"' || c == b'\'' || c == b'<' || c == b'>' {
                break;
            }
            j += 1;
        }
        let mut candidate = &text[s..j];
        candidate =
            candidate.trim_end_matches(|ch: char| matches!(ch, ')' | ']' | '}' | ',' | '.' | ';'));
        let candidate = candidate.replace("&amp;", "&");
        if Url::parse(&candidate).is_ok() {
            out.push(candidate);
        }
        i = j.max(i + 1);
    }
    out
}

fn parse_total_pages(text: &str) -> Option<usize> {
    let idx = text.find("Page ")?;
    let rest = &text[idx + 5..];
    let out_idx = rest.find(" out of ")?;
    let total_part = &rest[out_idx + 8..];
    let mut digits = String::new();
    for ch in total_part.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else {
            break;
        }
    }
    digits.parse::<usize>().ok()
}

pub async fn fetch_ghostarchive_urls(
    client: &reqwest::Client,
    domains: &[String],
    rps: u32,
    concurrency: usize,
    pb: Option<ProgressBar>,
) -> Result<Vec<String>> {
    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(rps.max(1)).unwrap(),
    )));
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut out = Vec::new();
    let mut tasks = FuturesUnordered::new();

    for d in domains {
        let dom = normalize_domain(d);
        let c = client.clone();
        let l = limiter.clone();
        let s = sem.clone();
        let p = pb.clone();
        tasks.push(async move {
            let mut acc = Vec::new();
            let term = form_urlencoded::byte_serialize(dom.as_bytes()).collect::<String>();

            let _g = s.acquire().await.unwrap();
            l.until_ready().await;
            let first_url = format!("https://ghostarchive.org/search?term={term}&page=1");
            let first = match c.get(&first_url).send().await {
                Ok(r) => r,
                Err(_) => return Ok::<_, anyhow::Error>(acc),
            };
            if !first.status().is_success() {
                return Ok::<_, anyhow::Error>(acc);
            }
            let first_text = match first.text().await {
                Ok(t) => t,
                Err(_) => return Ok::<_, anyhow::Error>(acc),
            };
            let total_pages = parse_total_pages(&first_text).unwrap_or(1).min(20);

            for u in extract_urls(&first_text) {
                if let Ok(url) = Url::parse(&u) {
                    if url.host_str() == Some("ghostarchive.org") {
                        continue;
                    }
                    if host_matches_domain(&url, &dom) {
                        acc.push(u);
                    }
                }
            }
            if let Some(p) = &p {
                p.inc(1);
            }

            for page in 2..=total_pages {
                let _g = s.acquire().await.unwrap();
                l.until_ready().await;
                let url = format!("https://ghostarchive.org/search?term={term}&page={page}");
                let resp = match c.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if !resp.status().is_success() {
                    break;
                }
                let text = match resp.text().await {
                    Ok(t) => t,
                    Err(_) => break,
                };
                for u in extract_urls(&text) {
                    if let Ok(url) = Url::parse(&u) {
                        if url.host_str() == Some("ghostarchive.org") {
                            continue;
                        }
                        if host_matches_domain(&url, &dom) {
                            acc.push(u);
                        }
                    }
                }
                if let Some(p) = &p {
                    p.inc(1);
                }
                if !text.contains("Next Page") {
                    break;
                }
            }

            acc.sort();
            acc.dedup();
            Ok::<_, anyhow::Error>(acc)
        });
    }

    while let Some(v) = tasks.next().await {
        out.extend(v?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}
