use std::path::PathBuf;
use std::time::Duration;

use ahash::AHashSet;
use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use colored::*;
use dotenvy::dotenv;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use url::Url;

mod sources;
use sources::alienvault::fetch_alienvault_urls;
use sources::commoncrawl::fetch_commoncrawl_urls;
use sources::ghostarchive::fetch_ghostarchive_urls;
use sources::urlscan::fetch_urlscan_urls;
use sources::virustotal::fetch_virustotal_urls;
use sources::wayback::{fetch_wayback_captures, fetch_wayback_urls, WaybackOpts};

#[derive(Clone, ValueEnum, Debug, PartialEq)]
enum SourceKind {
    Wayback,
    CommonCrawl,
    AlienVault,
    UrlScan,
    VirusTotal,
    GhostArchive,
}

#[derive(Subcommand, Debug)]
enum Command {
    WaybackCaptures(WaybackCapturesArgs),
}

#[derive(Parser, Debug)]
struct WaybackCapturesArgs {
    #[arg(
        short = 'd',
        long = "domain",
        help = "Домен/поддомен или URL (https://...) для поиска",
        conflicts_with = "domains_file"
    )]
    domain: Option<String>,

    #[arg(
        short = 'f',
        long = "domains-file",
        help = "Файл со списком доменов",
        value_name = "FILE"
    )]
    domains_file: Option<PathBuf>,

    #[arg(
        short = 'o',
        long = "output",
        help = "Файл для сохранения URL",
        value_name = "FILE"
    )]
    output: Option<PathBuf>,

    #[arg(
        long = "concurrency",
        help = "Глобальная конкуренция запросов",
        default_value_t = 64
    )]
    concurrency: usize,

    #[arg(
        long = "rps",
        help = "Ограничение rps на источник",
        default_value_t = 1
    )]
    rps: u32,

    #[arg(
        long = "timeout-secs",
        help = "Таймаут HTTP-запросов (сек)",
        default_value_t = 30
    )]
    timeout_secs: u64,

    #[arg(
        long = "wayback-limit",
        help = "Ограничить число результатов CDX (полезно для отладки)",
        value_name = "N"
    )]
    wayback_limit: Option<usize>,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Быстрый агрегатор URL из архивов и источников OSINT", long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[arg(
        short = 'd',
        long = "domain",
        help = "Домен/поддомен или URL (https://...) для поиска",
        conflicts_with = "domains_file"
    )]
    domain: Option<String>,

    #[arg(
        short = 'f',
        long = "domains-file",
        help = "Файл со списком доменов",
        value_name = "FILE"
    )]
    domains_file: Option<PathBuf>,

    #[arg(
        short = 'o',
        long = "output",
        help = "Файл для сохранения URL",
        value_name = "FILE"
    )]
    output: Option<PathBuf>,

    #[arg(
        long = "env-file",
        help = "Путь к .env с ключами API",
        value_name = "FILE"
    )]
    env_file: Option<PathBuf>,

    #[arg(
        long = "concurrency",
        help = "Глобальная конкуренция запросов",
        default_value_t = 64
    )]
    concurrency: usize,

    #[arg(
        long = "rps",
        help = "Ограничение rps на источник",
        default_value_t = 1
    )]
    rps: u32,

    #[arg(long = "sources", value_enum, action = ArgAction::Append, value_delimiter = ',', help = "Источники", default_values_t = vec![SourceKind::Wayback, SourceKind::CommonCrawl, SourceKind::AlienVault, SourceKind::UrlScan, SourceKind::VirusTotal, SourceKind::GhostArchive])]
    sources: Vec<SourceKind>,

    #[arg(
        long = "timeout-secs",
        help = "Таймаут HTTP-запросов (сек)",
        default_value_t = 30
    )]
    timeout_secs: u64,

    #[arg(
        long = "commoncrawl-indices",
        help = "Сколько индексов CommonCrawl опрашивать (чем меньше, тем быстрее)",
        default_value_t = 3
    )]
    commoncrawl_indices: usize,

    #[arg(
        long = "wayback-limit",
        help = "Ограничить число результатов CDX (полезно для отладки)",
        value_name = "N"
    )]
    wayback_limit: Option<usize>,

    #[arg(
        long = "wayback-page-size",
        help = "Размер страницы CDX для Wayback (limit на запрос)",
        default_value_t = 10000
    )]
    wayback_page_size: usize,

    #[command(subcommand)]
    cmd: Option<Command>,
}

fn normalize_target(input: &str) -> String {
    let s = input.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        if let Ok(u) = Url::parse(s) {
            if let Some(h) = u.host_str() {
                return h.trim_end_matches('.').to_string();
            }
        }
    }
    let s = s
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let s = s.split('/').next().unwrap_or(s);
    s.trim_end_matches('.').to_string()
}

async fn read_domains(
    domain: &Option<String>,
    domains_file: &Option<PathBuf>,
) -> Result<Vec<String>> {
    if let Some(d) = domain {
        return Ok(vec![normalize_target(d)]);
    }
    if let Some(path) = domains_file {
        let text: String = tokio::fs::read_to_string(path).await?;
        let mut list: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(normalize_target)
            .collect();
        list.sort();
        list.dedup();
        return Ok(list);
    }
    Err(anyhow!("Не указан домен"))
}

fn pb(style: &str, len: Option<u64>) -> ProgressBar {
    let bar = match len {
        Some(l) => ProgressBar::new(l),
        None => ProgressBar::new_spinner(),
    };
    bar.set_style(ProgressStyle::with_template(style).unwrap());
    bar
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(p) = &cli.env_file {
        let _ = dotenvy::from_path(p);
    } else {
        let _ = dotenv();
    }
    let m = MultiProgress::new();
    let title = format!(
        "{} {}",
        "rust-wayback".bold().bright_cyan(),
        env!("CARGO_PKG_VERSION").bright_black()
    );
    println!("{}", title);

    if let Some(cmd) = cli.cmd {
        match cmd {
            Command::WaybackCaptures(args) => {
                let domains = read_domains(&args.domain, &args.domains_file).await?;
                let client = reqwest::Client::builder()
                    .user_agent("rust-wayback/0.1")
                    .connect_timeout(Duration::from_secs(args.timeout_secs))
                    .timeout(Duration::from_secs(args.timeout_secs))
                    .build()?;

                let b = m.add(pb("{spinner:.green} {msg}", None));
                b.set_message("Wayback: поиск captures");
                let opts = WaybackOpts {
                    rps: args.rps,
                    concurrency: args.concurrency,
                };
                let res = fetch_wayback_captures(
                    &client,
                    &domains,
                    opts,
                    Some(b.clone()),
                    args.wayback_limit,
                )
                .await?;
                let msg = format!("Wayback captures: найдено {}", res.len());
                b.finish_with_message(msg);

                if let Some(path) = &args.output {
                    tokio::fs::write(path, res.join("\n")).await?;
                    println!("{} {}", "Сохранено:".bright_green(), path.to_string_lossy());
                } else {
                    for u in &res {
                        println!("{}", u);
                    }
                }
                return Ok(());
            }
        }
    }

    let domains = read_domains(&cli.domain, &cli.domains_file).await?;
    println!("Wayback: доменов для поиска: {}", domains.len());
    let client = reqwest::Client::builder()
        .user_agent("rust-wayback/0.1")
        .connect_timeout(Duration::from_secs(cli.timeout_secs))
        .timeout(Duration::from_secs(cli.timeout_secs))
        .build()?;

    let mut urls: AHashSet<String> = AHashSet::default();

    if cli.sources.contains(&SourceKind::Wayback) {
        let b = m.add(pb("{spinner:.green} {msg}", None));
        b.set_message("Wayback: сбор URL");
        let opts = WaybackOpts {
            rps: cli.rps,
            concurrency: cli.concurrency,
        };
        match fetch_wayback_urls(
            &client,
            &domains,
            opts,
            Some(b.clone()),
            cli.wayback_limit,
            cli.wayback_page_size,
        )
        .await
        {
            Ok(res) => {
                let msg = format!("Wayback: найдено {}", res.len());
                b.finish_with_message(msg);
                for u in res {
                    urls.insert(u);
                }
            }
            Err(e) => {
                b.finish_with_message(format!("Wayback: ошибка ({})", e).red().to_string());
            }
        }
    }

    if cli.sources.contains(&SourceKind::CommonCrawl) {
        let b = m.add(pb("{spinner:.green} {msg}", None));
        b.set_message("CommonCrawl: сбор URL");
        match fetch_commoncrawl_urls(
            &client,
            &domains,
            cli.rps,
            cli.concurrency,
            cli.commoncrawl_indices,
            Some(b.clone()),
        )
        .await
        {
            Ok(res) => {
                let msg = format!("CommonCrawl: найдено {}", res.len());
                b.finish_with_message(msg);
                for u in res {
                    urls.insert(u);
                }
            }
            Err(e) => {
                b.finish_with_message(format!("CommonCrawl: ошибка ({})", e).red().to_string());
            }
        }
    }

    if cli.sources.contains(&SourceKind::AlienVault) {
        let b = m.add(pb("{spinner:.green} {msg}", None));
        b.set_message("AlienVault: сбор URL");
        match fetch_alienvault_urls(&client, &domains, cli.rps, cli.concurrency, Some(b.clone()))
            .await
        {
            Ok(res) => {
                let msg = format!("AlienVault: найдено {}", res.len());
                b.finish_with_message(msg);
                for u in res {
                    urls.insert(u);
                }
            }
            Err(e) => {
                b.finish_with_message(format!("AlienVault: ошибка ({})", e).red().to_string());
            }
        }
    }

    if cli.sources.contains(&SourceKind::UrlScan) {
        let b = m.add(pb("{spinner:.green} {msg}", None));
        b.set_message("URLScan: сбор URL");
        match fetch_urlscan_urls(&client, &domains, cli.rps, cli.concurrency, Some(b.clone())).await
        {
            Ok(res) => {
                let msg = format!("URLScan: найдено {}", res.len());
                b.finish_with_message(msg);
                for u in res {
                    urls.insert(u);
                }
            }
            Err(e) => {
                b.finish_with_message(format!("URLScan: ошибка ({})", e).red().to_string());
            }
        }
    }

    if cli.sources.contains(&SourceKind::VirusTotal) {
        let b = m.add(pb("{spinner:.green} {msg}", None));
        b.set_message("VirusTotal: сбор URL");
        match fetch_virustotal_urls(&client, &domains, cli.rps, cli.concurrency, Some(b.clone()))
            .await
        {
            Ok(res) => {
                let msg = format!("VirusTotal: найдено {}", res.len());
                b.finish_with_message(msg);
                for u in res {
                    urls.insert(u);
                }
            }
            Err(e) => {
                b.finish_with_message(format!("VirusTotal: ошибка ({})", e).red().to_string());
            }
        }
    }

    if cli.sources.contains(&SourceKind::GhostArchive) {
        let b = m.add(pb("{spinner:.green} {msg}", None));
        b.set_message("GhostArchive: сбор URL");
        match fetch_ghostarchive_urls(&client, &domains, cli.rps, cli.concurrency, Some(b.clone()))
            .await
        {
            Ok(res) => {
                let msg = format!("GhostArchive: найдено {}", res.len());
                b.finish_with_message(msg);
                for u in res {
                    urls.insert(u);
                }
            }
            Err(e) => {
                b.finish_with_message(format!("GhostArchive: ошибка ({})", e).red().to_string());
            }
        }
    }

    println!(
        "{} {}",
        "Всего уникальных URL:".bright_green(),
        urls.len().to_string().bold()
    );

    let mut sorted: Vec<String> = urls.iter().cloned().collect();
    sorted.sort();
    if let Some(path) = &cli.output {
        tokio::fs::write(path, sorted.join("\n")).await?;
        println!("{} {}", "Сохранено:".bright_green(), path.to_string_lossy());
    } else {
        for u in &sorted {
            println!("{}", u);
        }
    }

    Ok(())
}
