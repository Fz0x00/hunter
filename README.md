# Hunter

Asset discovery & version extraction for Electron/CEF apps — pure Go, zero runtime deps.

Part of [ChromiumHunter](https://github.com/Fz0x00/chromiumHunter): "which of my apps ship a stale Chromium, and which CVEs does that expose me to?"

## Commands

| Command | Purpose |
|---|---|
| `scan` | Scan the local filesystem for apps with embedded Chromium (Electron / CEF / forks) |
| `inspect <path>` | Extract framework type + Electron/Chromium version from a local app bundle |
| `inspect-list` | Batch download & inspect apps from `apps.json` registry (with `-list` for dry-run listing) |
| `version-check` | Resolve latest version signatures from update feeds, GitHub releases, version APIs |
| `risk` | Match app versions against [ChromiumIntel](https://github.com/Fz0x00/chromium-intel) CVE database |
| `osv-check` | Query [OSV](https://osv.dev) for Electron framework CVEs (needs `electron-map.json`) |
| `catalog` | Unified version catalog: config layer + resolved signature + verified versions |
| `query` | Query scan history from the SQLite database (`-stats` for live stats) |

## SQLite database (`hunter.db`)

Use with `-db` on `version-check`, `inspect-list`, `catalog`, `query`.

| Table | Written by | Contents |
|---|---|---|
| `scans` | `scan` / `inspect` | Local scan observations |
| `app_events` | `inspect-list` | Downloaded app: app_version / electron_version / chromium_version |
| `app_catalog` | `version-check` (config+signature) + `inspect-list` (verified versions) | One row per app: download config (`url`, `github`, `release_feed`, `version_api`), `resolved_signature`, `last_checked` / `last_changed`, verified versions + `verified_at` |

### Key workflow

```bash
# 1. resolve latest signatures (light HTTP, no downloads)
hunter version-check -db hunter.db -output versions.json -platform linux apps.json

# 2. inspect only changed apps (incremental — new versions only)
hunter inspect-list -db hunter.db -only "$CHANGED" -electron-map electron-map.json

# 3. unified catalog report (config + signature + verified versions per app)
hunter catalog -db hunter.db -output catalog.json
hunter catalog -db hunter.db -stale    # apps needing a fresh inspect
```

`resolved_signature` + `last_changed` drive the incremental logic: an app needs re-inspection iff `last_changed > verified_at`.

## Adding an app

Add one entry to `apps.json` — no code changes:

```json
{
  "name": "Example",
  "publisher": "...",
  "url": "https://example.com/download.pkg",       // direct download URL
  "github": "org/repo",                            // GitHub releases (asset_pattern to filter)
  "release_feed": "https://...",                   // JSON feed (full_path / latest_version)
  "version_api": "https://...",                     // returns {"version": "x.y.z"} (exact_version_url)
  "platform": "macos|windows|linux|any"
}
```

`component` is optional; leaving it out falls back to auto-detection from feed format.

## CI

`.github/workflows/monitor.yml` (GitHub Actions):

1. Playwright collects dynamic URLs → `dynamic-urls.json`
2. `version-check` compares against tracked `versions.json`, emits changed list
3. Only changed apps go through `inspect-list` (download + extract Chromium version)
4. `catalog` exports `catalog.json`; commits version tracking files

Manual `workflow_dispatch` supports `force: true` to bypass incremental logic.

## Development

```bash
go build . && go vet ./... && go test ./...
```