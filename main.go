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
  version                          Show version

Scan flags:
  -json <path>                     Write JSON report to path
  -electron-map <path>             Path to electron-map.json (for fallback)

Inspect flags:
  -json <path>                     Write JSON report to path
  -electron-map <path>             Path to electron-map.json
  -keep                            Keep downloaded files (don't cleanup)
  -timeout <duration>              Download timeout (default 5m)

Examples:
  %s scan                                    # scan /Applications
  %s scan -json report.json /Applications
  %s inspect https://example.com/App.zip
  %s inspect-list apps.json -json results.json
`, version, exe, exe, exe, exe, exe)
}
