package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func runInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	var (
		jsonOut string
		emPath  string
		keep    bool
		timeout time.Duration
	)
	fs.StringVar(&jsonOut, "json", "", "write JSON report to path")
	fs.StringVar(&emPath, "electron-map", defaultEMPath(), "path to electron-map.json")
	fs.BoolVar(&keep, "keep", false, "keep downloaded files")
	fs.DurationVar(&timeout, "timeout", 5*time.Minute, "download timeout")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: hunter inspect <url|github://owner/repo>")
		os.Exit(1)
	}

	input := fs.Arg(0)
	entry := AppEntry{Name: "inspect-target"}

	if strings.HasPrefix(input, "github://") {
		entry.GitHub = strings.TrimPrefix(input, "github://")
		entry.Name = entry.GitHub
	} else {
		entry.URL = input
	}
	apps, err := doInspect(entry, emPath, keep, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	printTable(apps)

	if jsonOut != "" {
		result := newInspectResult(apps, entry)
		if err := writeJSON(jsonOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[report] JSON saved to %s\n", jsonOut)
	}
}

func runInspectList(args []string) {
	fs := flag.NewFlagSet("inspect-list", flag.ExitOnError)
	var (
		jsonOut string
		dbPath  string
		emPath  string
		keep    bool
		timeout time.Duration
	)
	fs.StringVar(&jsonOut, "json", "", "write JSON report to path")
	fs.StringVar(&dbPath, "db", "", "SQLite database path (stores scan history)")
	fs.StringVar(&emPath, "electron-map", defaultEMPath(), "path to electron-map.json")
	fs.BoolVar(&keep, "keep", false, "keep downloaded files")
	fs.DurationVar(&timeout, "timeout", 10*time.Minute, "download timeout per app")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: hunter inspect-list <apps.json>")
		os.Exit(1)
	}

	reg, err := loadRegistry(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}

	var em *ElectronMap
	if info, err := os.Stat(emPath); err == nil && !info.IsDir() {
		if m, err := LoadElectronMap(emPath); err == nil {
			em = m
		}
	}

	var allApps []App
	for _, entry := range reg.Apps {
		fmt.Fprintf(os.Stderr, "\n[inspect] === %s ===\n", entry.Name)
		apps, err := doInspect(entry, emPath, keep, timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s: %v\n", entry.Name, err)
			continue
		}
		if em == nil {
			if m, _ := LoadElectronMap(emPath); m != nil {
				em = m
			}
		}
		allApps = append(allApps, apps...)
		printTable(apps)
	}

	result := newScanResult(allApps, "inspect-list", fs.Arg(0))

	if dbPath != "" {
		db, err := OpenDB(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] failed to open db: %v\n", err)
			os.Exit(1)
		}
		scanID, err := db.InsertScan(result)
		db.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] failed to insert scan: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\n[db] scan #%d saved to %s\n", scanID, dbPath)
	}

	if jsonOut != "" {
		if err := writeJSON(jsonOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\n[report] JSON saved to %s (%d apps)\n", jsonOut, len(allApps))
	}
}

func doInspect(entry AppEntry, emPath string, keep bool, timeout time.Duration) ([]App, error) {
	url, tag, err := entry.resolveDownloadURL()
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	if tag != "" {
		fmt.Fprintf(os.Stderr, "[fetch] resolved %s@%s -> %s\n", entry.GitHub, tag, url)
	}

	tmpDir, err := os.MkdirTemp("", "hunter-*")
	if err != nil {
		return nil, err
	}
	if !keep {
		defer os.RemoveAll(tmpDir)
	}

	fmt.Fprintf(os.Stderr, "[fetch] downloading...\n")
	archivePath, err := downloadFile(url, tmpDir, timeout)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}

	extractDir := filepath.Join(tmpDir, "extracted")
	fmt.Fprintf(os.Stderr, "[extract] %s -> %s\n", filepath.Base(archivePath), extractDir)
	if err := extractArchive(archivePath, extractDir); err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	appPaths := findAppsInDir(extractDir)
	if len(appPaths) == 0 {
		return nil, fmt.Errorf("no .app found in %s", filepath.Base(archivePath))
	}

	fmt.Fprintf(os.Stderr, "[scan] found %d .app bundle(s)\n", len(appPaths))

	var em *ElectronMap
	if m, err := LoadElectronMap(emPath); err == nil {
		em = m
	}

	var apps []App
	for _, appPath := range appPaths {
		app, ok := inspectApp(appPath)
		if !ok {
			continue
		}
		if entry.Name != "inspect-target" {
			app.Name = entry.Name
		}
		extractVersion(&app, em)
		apps = append(apps, app)
	}
	if len(apps) == 0 {
		return nil, fmt.Errorf("no Electron app found")
	}
	return apps, nil
}

type InspectResult struct {
	Source   string `json:"source"`
	ScanTime string `json:"scan_time"`
	Total    int    `json:"total"`
	Apps     []App  `json:"apps"`
}

func newInspectResult(apps []App, entry AppEntry) InspectResult {
	return InspectResult{
		Source:   entry.URL,
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		Total:    len(apps),
		Apps:     apps,
	}
}
