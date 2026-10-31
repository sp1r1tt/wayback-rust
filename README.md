# rust-wayback

A fast Rust CLI tool for collecting domain-related URLs from multiple archival and threat intelligence sources. Inspired by tools such as waybackurls, gau, and waymore, it features configurable request rate limits and high concurrency.

Supports URL aggregation from:

- Wayback Machine (`web.archive.org`)
- Common Crawl (`index.commoncrawl.org`)
- AlienVault OTX (`otx.alienvault.com`)
- URLScan (`urlscan.io`)
- VirusTotal (`virustotal.com`)
- Ghostarchive (`ghostarchive.org`)

## Installation

Rust and Cargo are required.

Build the project:

```bash
cargo build --release
```

Run the compiled binary:

- Windows: `target\release\rust-wayback.exe`
- Linux/macOS: `target/release/rust-wayback`

## Quick Start

Collect URLs for a domain from all available sources (default behavior) and save them to a file:

```bash
cargo run --release -- --domain example.com --output out.txt
```

To limit the sources, use `--sources` (you can specify it multiple times):

```bash
cargo run --release -- --domain example.com --sources wayback --output out.txt
```

Collect URLs only from Wayback Machine and Common Crawl:

```bash
cargo run --release -- --domain example.com --sources wayback --sources common-crawl --output out.txt
```

## Environment Variables (.env)

Some sources require API keys. The tool can load keys from a `.env` file in the project root or from a file specified using `--env-file`.

Create a `.env` file (a template is included in the repository) and add your API keys:

```env
OTX_API_KEY=...
URLSCAN_API_KEY=...
VT_API_KEY=...
```

Run the tool with an explicitly specified `.env` file:

```bash
cargo run --release -- --env-file .env --domain example.com --output out.txt
```

## Usage

```text
rust-wayback.exe [OPTIONS]

Options:
  -d, --domain <DOMAIN>            Domain, subdomain, or URL (https://...) to search
  -f, --domains-file <FILE>        File containing a list of domains (one per line)
  -o, --output <FILE>              File to save collected URLs (prints to stdout if omitted)
      --env-file <FILE>            Path to the .env file containing API keys
      --concurrency <CONCURRENCY>  Global maximum number of concurrent requests (default: 64)
      --rps <RPS>                  Request rate limit per source (default: 1)
      --timeout-secs <SECONDS>     HTTP request timeout in seconds (default: 30)
      --commoncrawl-indices <N>    Number of Common Crawl indexes to query (default: 3)
      --wayback-limit <N>          Limit the number of CDX results (useful for debugging)
      --wayback-page-size <N>      Number of CDX results per request (default: 5000)
      --sources <SOURCES>          Sources to use (can be specified multiple times or as a comma-separated list)
                                   Possible values:
                                   wayback, common-crawl, alien-vault, url-scan, virus-total, ghost-archive
```

## Commands

### wayback-captures

A Wayback-specific mode that returns snapshot URLs instead of original URLs, using the following format:

`https://web.archive.org/web/<timestamp>/<original>`

Examples:

```bash
rust-wayback.exe wayback-captures --domain example.com --output captures.txt
```

```bash
rust-wayback.exe wayback-captures --domains-file domains.txt --rps 1 --concurrency 64 --output captures.txt
```

### Data Sources and Implementation Details

- `wayback`
  - Collects URLs through the CDX API.
  - Uses `output=txt`, `fl=original`, `collapse=urlkey`, and pagination via `offset`.
  - Requests are currently sent without delays or retry logic.

- `common-crawl`
  - Searches Common Crawl indexes and processes JSON Lines responses.

- `alien-vault`
  - Retrieves domain URL lists through the AlienVault OTX API.
  - API key: `OTX_API_KEY` (optional, but recommended for improved stability and rate limits).
  - If the input contains subdomains or full URLs, the tool extracts the hostname and additionally queries the root domain (e.g., `iris-api.circle.com` → `circle.com`).

- `url-scan`
  - Uses the URLScan Search API.
  - API key: `URLSCAN_API_KEY` (optional, but recommended for higher rate limits).

- `virus-total`
  - Retrieves domain relationships and URLs through the VirusTotal API.
  - API key: `VT_API_KEY` (required to retrieve results).

- `ghost-archive`
  - Parses Ghostarchive search pages in the following format: `https://ghostarchive.org/search?term=<domain>&page=<n>`.
  - No API keys are required.

## Performance and Rate Limits

- `--rps` controls the request rate for each source, helping avoid rate limits.
- `--concurrency` sets the maximum number of concurrent HTTP requests.
- `--timeout-secs` prevents requests from hanging indefinitely and allows the tool to move on to other sources more quickly.
- Common Crawl is often the slowest source. Reduce `--commoncrawl-indices` (e.g., set it to `1`) to speed up scans.
- Results are deduplicated and sorted when written to the output file.

## Examples

Collect URLs for multiple domains from a file:

```bash
cargo run --release -- --domains-file domains.txt --output out.txt
```

Use Ghostarchive only:

```bash
cargo run --release -- --domain example.com --sources ghost-archive --output out.txt
```

Run in a more conservative mode:

```bash
cargo run --release -- --domain example.com --rps 1 --concurrency 8 --output out.txt
```

## Notes

- If API keys are not provided, the corresponding sources may return no results or operate with reduced functionality, but the tool should continue running without crashing.
- Large domains queried across all sources may produce a substantial number of results. Use `--output` to save them to a file instead of printing everything to stdout.

Use this tool only for domains you own or are authorized to assess, and respect the terms of service and rate limits of each data source.
