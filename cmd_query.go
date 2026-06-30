package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// query 命令：从 SQLite 数据库查询扫描结果
//
// 用法：
//   hunter query -db hunter.db                        # 列出所有应用最新快照
//   hunter query -db hunter.db -name Lark             # 查询某应用历史版本
//   hunter query -db hunter.db -old 130               # 查询 Chromium <= 130 的应用
//   hunter query -db hunter.db -stats                 # 数据库统计信息
//   hunter query -db hunter.db -json                  # JSON 输出
func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	var (
		dbPath  string
		name    string
		oldMax  int
		stats   bool
		jsonOut bool
	)
	fs.StringVar(&dbPath, "db", "hunter.db", "SQLite database path")
	fs.StringVar(&name, "name", "", "filter by app name (fuzzy match)")
	fs.IntVar(&oldMax, "old", 0, "find apps with Chromium major version <= N")
	fs.BoolVar(&stats, "stats", false, "show database statistics")
	fs.BoolVar(&jsonOut, "json", false, "output as JSON")
	fs.Parse(args)

	if dbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: hunter query -db <path> [filters]")
		os.Exit(1)
	}

	db, err := OpenDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if stats {
		printStats(db, jsonOut)
		return
	}

	var rows []AppRow
	switch {
	case name != "":
		rows, err = db.QueryByName(name)
	case oldMax > 0:
		rows, err = db.QueryByChromium(0, oldMax)
	default:
		rows, err = db.QueryLatest()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] query: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		out, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(out))
		return
	}

	printQueryTable(rows)
}

func printQueryTable(rows []AppRow) {
	if len(rows) == 0 {
		fmt.Println("(no results)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tVER\tFRAMEWORK\tCHROMIUM\tELECTRON\tSCAN_TIME")
	fmt.Fprintln(w, strings.Repeat("-", 16)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 16)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 20))
	for _, r := range rows {
		chrome := r.ChromiumVersion
		if chrome == "" {
			chrome = "?"
		}
		electron := r.ElectronVersion
		if electron == "" {
			electron = "-"
		}
		appVer := r.AppVersion
		if appVer == "" {
			appVer = "-"
		}
		scanTime := r.ScanTime
		if len(scanTime) >= 10 {
			scanTime = scanTime[:10]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			trunc(r.Name, 28), trunc(appVer, 12), r.Framework, chrome, electron, scanTime)
	}
	w.Flush()
}

func printStats(db *DB, jsonOut bool) {
	stats, err := db.QueryStats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] stats: %v\n", err)
		os.Exit(1)
	}
	if jsonOut {
		out, _ := json.MarshalIndent(stats, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Printf("Total scans:        %d\n", stats.TotalScans)
	fmt.Printf("Unique apps:        %d\n", stats.TotalApps)
	fmt.Printf("Last scan:          %s\n", stats.LastScanTime)
	fmt.Printf("Oldest Chromium:    %s\n", stats.OldestChromium)
	fmt.Printf("Newest Chromium:    %s\n", stats.NewestChromium)
	fmt.Println("Framework breakdown:")
	for fw, n := range stats.FrameworkBreakdown {
		fmt.Printf("  %-16s %d\n", fw, n)
	}
}
