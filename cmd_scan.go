package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var (
		jsonOut string
		dbPath  string
		emPath  string
	)
	fs.StringVar(&jsonOut, "json", "", "write JSON report to `path`")
	fs.StringVar(&dbPath, "db", "", "SQLite database `path` (stores scan history)")
	fs.StringVar(&emPath, "electron-map", defaultEMPath(), "path to electron-map.json")
	fs.Parse(args)

	roots := fs.Args()
	if len(roots) == 0 {
		roots = defaultScanPaths()
	}

	var em *ElectronMap
	if info, err := os.Stat(emPath); err == nil && !info.IsDir() {
		if m, err := LoadElectronMap(emPath); err == nil {
			em = m
		}
	}

	fmt.Fprintf(os.Stderr, "[scan] hunter v%s — scanning %s\n", version, strings.Join(roots, ", "))
	start := time.Now()
	apps := discoverApps(roots)
	fmt.Fprintf(os.Stderr, "[scan] found %d Chromium-embedded apps, extracting versions...\n", len(apps))

	for i := range apps {
		extractVersion(&apps[i], em)
	}
	fmt.Fprintf(os.Stderr, "[scan] done in %s\n", time.Since(start).Round(time.Millisecond))

	printTable(apps)

	result := newScanResult(apps, "local", strings.Join(roots, ","))

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
		fmt.Fprintf(os.Stderr, "[db] scan #%d saved to %s\n", scanID, dbPath)
	}

	if jsonOut != "" {
		if err := writeJSON(jsonOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "[error] failed to write JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[report] JSON saved to %s\n", jsonOut)
	}
}

func printTable(apps []App) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tFRAMEWORK\tCHROMIUM\tVERSION\tDETECTION\tMETHOD")
	fmt.Fprintln(w, strings.Repeat("-", 16)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 12))
	for _, a := range apps {
		chrome := a.ChromiumVersion
		if chrome == "" {
			chrome = "?"
		}
		version := a.ElectronVersion
		if a.CEFVersion != "" {
			version = a.CEFVersion
		}
		if version == "" {
			version = "-"
		}
		det := string(a.Detection)
		method := string(a.ExtractionMethod)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			trunc(a.Name, 28), a.Framework, chrome, version, det, method)
	}
	w.Flush()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func writeJSON(path string, result any) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func defaultEMPath() string {
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "..", "electron-map.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "../electron-map.json"
}
