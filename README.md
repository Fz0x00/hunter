# hunter

Chromium supply chain asset scanner — local & remote inspection of Electron/CEF apps.

Part of the [ChromiumHunter](https://github.com/Fz0x00/chromium-intel) project.

## What it does

`hunter` finds applications with embedded Chromium engines (Electron, Electron forks, Qt WebEngine) and extracts the exact Chromium version they ship. Combined with the CVE intelligence from `chromium-intel`, this closes the "which of my apps are running a stale browser engine?" gap that existing SCA tools miss.

## Install

```bash
go build -o hunter .
```

Zero external dependencies — pure Go standard library.

## Commands

### `scan` — scan local filesystem

```bash
hunter scan                              # scan /Applications + ~/Applications
hunter scan /Applications -json out.json
```

### `inspect` — download & inspect a package

```bash
hunter inspect https://desktop.figma.com/mac/Figma.zip
hunter inspect github://obsidianmd/obsidian-releases   # GitHub Releases auto-resolve
```

Supports ZIP (pure Go), DMG (hdiutil on macOS / 7z on Linux), PKG (pkgutil on macOS).

### `inspect-list` — batch inspect from registry

```bash
hunter inspect-list apps.json -json results.json
```

See [`apps.json`](apps.json) for the registry format (direct URLs or GitHub repos).

## Version extraction strategy (3-layer fallback)

For each discovered `.app`:

| # | Method | How | When |
|---|---|---|---|
| 1 | **framework_path** | Read `Versions/X.X.X.X/` dir name | Some apps (Lark) embed it |
| 2 | **binary_strings** | Grep `Chrome/X.X.X.X` from framework binary | Most apps (VSCode, Cursor, Figma...) |
| 3 | **electron_mapping** | Read Electron version from Info.plist → lookup table | Fallback |

## CI

A GitHub Actions workflow (`.github/workflows/inspect-apps.yml`) runs weekly, downloads all apps in `apps.json`, extracts their Chromium version, and publishes a dashboard to GitHub Pages.

## Related

- [`chromium-intel`](https://github.com/Fz0x00/chromium-intel) — CVE intelligence collection (the other half)
