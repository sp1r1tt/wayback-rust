use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::ProgressBar;
use url::Url;

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct WaybackOpts {
    pub rps: u32,
    pub concurrency: usize,
}

pub async fn fetch_wayback_urls(
    client: &reqwest::Client,
    domains: &[String],
    _opts: WaybackOpts,
    pb: Option<ProgressBar>,
    _cdx_limit: Option<usize>,
    page_size: usize,
) -> Result<Vec<String>> {
    let mut acc: Vec<String> = Vec::new();
    let mut tasks = FuturesUnordered::new();

    for domain in domains {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }

        let c = client.clone();
        let p = pb.clone();
        tasks.push(async move {
            let mut out = Vec::new();
            let effective_page_size = page_size.max(1);
            let mut offset = 0usize;
            let mut retries = 3;

            loop {
                let mut u = Url::parse("https://web.archive.org/cdx/search/cdx").unwrap();
                u.query_pairs_mut()
                    .append_pair("url", &format!("{}/*", domain))
                    .append_pair("output", "txt")
                    .append_pair("fl", "original")
                    .append_pair("collapse", "urlkey")
                    .append_pair("limit", &effective_page_size.to_string())
                    .append_pair("offset", &offset.to_string());

                let resp = match c.get(u.as_str()).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        if retries > 0 {
                            retries -= 1;
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                        if let Some(p) = &p {
                            p.set_message(format!("Wayback: error {} - {}", domain, e));
                        }
                        break;
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    if status == 429 || status >= 500 {
                        if retries > 0 {
                            retries -= 1;
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    }
                    if let Some(p) = &p {
                        p.set_message(format!("Wayback: skipped {} (HTTP {})", domain, status));
                    }
                    break;
                }

                let text = match resp.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        if retries > 0 {
                            retries -= 1;
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                        if let Some(p) = &p {
                            p.set_message(format!("Wayback: error {} - {}", domain, e));
                        }
                        break;
                    }
                };

                let mut got = 0usize;
                for line in text.lines() {
                    let s = line.trim();
                    if s.is_empty() {
                        continue;
                    }
                    out.push(s.to_string());
                    got += 1;
                }

                if got == 0 {
                    break;
                }
                offset = offset.saturating_add(effective_page_size);
            }

            if let Some(p) = &p {
                p.inc(1);
            }
            out.sort();
            out.dedup();
            Ok::<_, anyhow::Error>(out)
        });
    }

    while let Some(r) = tasks.next().await {
        match r {
            Ok(v) => acc.extend(v),
            Err(_) => {}
        }
    }
    acc.sort();
    acc.dedup();
    Ok(acc)
}

pub async fn fetch_wayback_captures(
    client: &reqwest::Client,
    domains: &[String],
    _opts: WaybackOpts,
    pb: Option<ProgressBar>,
    _cdx_limit: Option<usize>,
) -> Result<Vec<String>> {
    let mut acc: Vec<String> = Vec::new();
    let mut tasks = FuturesUnordered::new();

    for domain in domains {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }

        let c = client.clone();
        let p = pb.clone();
        tasks.push(async move {
            let mut out = Vec::new();
            let mut u = Url::parse("https://web.archive.org/cdx/search/cdx").unwrap();
            u.query_pairs_mut()
                .append_pair("url", &domain)
                .append_pair("matchType", "host")
                .append_pair("output", "json")
                .append_pair("fl", "timestamp,original,statuscode")
                .append_pair("collapse", "digest");

            let resp = match c.get(u.as_str()).send().await {
                Ok(r) => r,
                Err(_) => {
                    if let Some(p) = &p {
                        p.set_message(format!("Wayback: skipped {}", domain));
                    }
                    return Ok::<_, anyhow::Error>(Vec::new());
                }
            };

            if !resp.status().is_success() {
                if let Some(p) = &p {
                    p.set_message(format!("Wayback: skipped {}", domain));
                }
                return Ok::<_, anyhow::Error>(Vec::new());
            }

            let text = match resp.text().await {
                Ok(t) => t,
                Err(_) => return Ok::<_, anyhow::Error>(Vec::new()),
            };

            let v: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => return Ok::<_, anyhow::Error>(Vec::new()),
            };

            let mut best: std::collections::HashMap<String, String> = std::collections::HashMap::default();
            if let Some(arr) = v.as_array() {
                for item in arr.iter().skip(1) {
                    let ts = item.get(0).and_then(|x| x.as_str());
                    let orig = item.get(1).and_then(|x| x.as_str());
                    let sc = item.get(2).and_then(|x| x.as_str()).unwrap_or("");
                    if ts.is_none() || orig.is_none() || sc.is_empty() {
                        continue;
                    }
                    let ts = ts.unwrap().to_string();
                    let orig = orig.unwrap().to_string();
                    match best.get_mut(&orig) {
                        None => {
                            best.insert(orig.clone(), ts);
                        }
                        Some(cur) => {
                            if ts > *cur {
                                *cur = ts;
                            }
                        }
                    }
                }
            }

            for (orig, ts) in best {
                out.push(format!("https://web.archive.org/web/{}/{}", ts, orig));
            }

            if let Some(p) = &p {
                p.inc(1);
            }
            Ok::<_, anyhow::Error>(out)
        });
    }

    while let Some(r) = tasks.next().await {
        match r {
            Ok(v) => acc.extend(v),
            Err(_) => {}
        }
    }
    acc.sort();
    acc.dedup();
    Ok(acc)
}
