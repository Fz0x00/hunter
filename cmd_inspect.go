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
		jsonOut     string
		dbPath      string
		emPath      string
		keep        bool
		list        bool
		only        string
		concurrency int
		timeout     time.Duration
	)
	fs.StringVar(&jsonOut, "json", "", "write JSON report to path")
	fs.StringVar(&dbPath, "db", "", "SQLite database path (stores scan history)")
	fs.StringVar(&emPath, "electron-map", defaultEMPath(), "path to electron-map.json")
	fs.BoolVar(&keep, "keep", false, "keep downloaded files")
	fs.BoolVar(&list, "list", false, "only resolve download URLs, do not download")
	fs.StringVar(&only, "only", "", "comma-separated app names to inspect (case-insensitive)")
	fs.IntVar(&concurrency, "concurrency", 1, "number of apps to inspect in parallel")
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

	// 过滤要检测的应用
	filter := map[string]bool{}
	if only != "" {
		for _, n := range strings.Split(only, ",") {
			filter[strings.ToLower(strings.TrimSpace(n))] = true
		}
	}

	if list {
		fmt.Printf("%-22s %-12s %s\n", "APP", "TYPE", "URL")
		fmt.Printf("%s\n", strings.Repeat("-", 80))
		ok, fail, skipped := 0, 0, 0
		for _, entry := range reg.Apps {
			if len(filter) > 0 && !filter[strings.ToLower(entry.Name)] {
				skipped++
				continue
			}
			url, tag, err := entry.resolveDownloadURL()
			typ := "direct"
			if entry.GitHub != "" {
				typ = "github"
			} else if entry.ReleaseFeed != "" {
				typ = "feed"
			}
			if err != nil {
				fmt.Printf("%-22s %-12s FAIL: %v\n", entry.Name, typ, err)
				fail++
			} else {
				notes := ""
				if tag != "" {
					notes = "tag=" + tag
				}
				fmt.Printf("%-22s %-12s %s %s\n", entry.Name, typ, url, notes)
				ok++
			}
		}
		fmt.Printf("\n%d ok, %d fail, %d skipped, %d total\n", ok, fail, skipped, ok+fail+skipped)
		return
	}

	// 筛选要检测的应用
	var toInspect []AppEntry
	for _, entry := range reg.Apps {
		if len(filter) > 0 && !filter[strings.ToLower(entry.Name)] {
			continue
		}
		toInspect = append(toInspect, entry)
	}

	if concurrency <= 1 {
		// 串行模式（默认，日志清晰）
		var allApps []App
		seen := make(map[string]bool)
		for _, entry := range toInspect {
			fmt.Fprintf(os.Stderr, "\n[inspect] === %s ===\n", entry.Name)
			apps, err := doInspect(entry, emPath, keep, timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[error] %s: %v\n", entry.Name, err)
				continue
			}
			for _, a := range apps {
				key := a.Name + "|" + a.ChromiumVersion
				if seen[key] {
					continue
				}
				seen[key] = true
				allApps = append(allApps, a)
			}
			printTable(apps)
		}
		finishInspectList(allApps, fs.Arg(0), dbPath, jsonOut)
		return
	}

	// 并行模式
	type result struct {
		entry AppEntry
		apps  []App
		err   error
	}
	results := make(chan result, len(toInspect))
	sem := make(chan struct{}, concurrency)
	for _, entry := range toInspect {
		go func(e AppEntry) {
			sem <- struct{}{}
			defer func() { <-sem }()
			apps, err := doInspect(e, emPath, keep, timeout)
			results <- result{e, apps, err}
		}(entry)
	}
	var allApps []App
	seen := make(map[string]bool)
	for i := 0; i < len(toInspect); i++ {
		r := <-results
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s: %v\n", r.entry.Name, r.err)
			continue
		}
		for _, a := range r.apps {
			key := a.Name + "|" + a.ChromiumVersion
			if seen[key] {
				continue
			}
			seen[key] = true
			allApps = append(allApps, a)
		}
		fmt.Fprintf(os.Stderr, "[done] %s — %d app(s)\n", r.entry.Name, len(r.apps))
		printTable(r.apps)
	}
	finishInspectList(allApps, fs.Arg(0), dbPath, jsonOut)
}

func finishInspectList(allApps []App, scope, dbPath, jsonOut string) {
	result := newScanResult(allApps, "inspect-list", scope)

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

// doInspect is the core inspect function used by both serial and parallel modes.
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
		// Debug: list what was actually extracted
		filepath.WalkDir(extractDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || path == extractDir {
				return nil
			}
			rel, _ := filepath.Rel(extractDir, path)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth <= 2 {
				fmt.Fprintf(os.Stderr, "  [debug] %s%s\n", rel, map[bool]string{true: "/", false: ""}[d.IsDir()])
			}
			return nil
		})
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
