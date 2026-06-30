package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const version = "0.2.0"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "scan":
			runScan(os.Args[2:])
			return
		case "inspect":
			runInspect(os.Args[2:])
			return
		case "inspect-list":
			runInspectList(os.Args[2:])
			return
		case "version-check":
			runVersionCheck(os.Args[2:])
			return
		case "query":
			runQuery(os.Args[2:])
			return
		case "version", "-v", "--version":
			fmt.Printf("hunter %s\n", version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}
	runScan(os.Args[1:])
}

func printHelp() {
	exe := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `hunter %s — Chromium supply chain asset scanner

Usage:
  %s <command> [flags] [args]

Commands:
  scan [paths...]                  Scan local filesystem for Electron/CEF apps
  inspect <url>                    Download & inspect a single app package
  inspect-list <apps.json>         Batch inspect from a JSON app registry
  version-check <apps.json>        Resolve URLs, compare with versions.json, report changed
  query                            Query scan history from SQLite database
  version                          Show version

Scan flags:
  -json <path>                     Write JSON report to path
  -db <path>                       Store results in SQLite database
  -electron-map <path>             Path to electron-map.json (for fallback)

Inspect flags:
  -json <path>                     Write JSON report to path
  -db <path>                       Store results in SQLite database
  -electron-map <path>             Path to electron-map.json
  -keep                            Keep downloaded files (don't cleanup)
  -timeout <duration>              Download timeout (default 5m)

Query flags:
  -db <path>                       SQLite database (default: hunter.db)
  -name <keyword>                  Filter by app name (fuzzy)
  -old <N>                         Find apps with Chromium major <= N
  -stats                           Show database statistics
  -json                            Output as JSON

Examples:
  %s scan -db hunter.db                          # scan and store
  %s inspect-list apps.json -db hunter.db        # inspect and store
  %s query -db hunter.db                         # list latest results
  %s query -db hunter.db -name Lark              # Lark version history
  %s query -db hunter.db -old 130                # vulnerable apps (old Chromium)
  %s query -db hunter.db -stats                  # database summary
`, version, exe, exe, exe, exe, exe, exe, exe)
}
