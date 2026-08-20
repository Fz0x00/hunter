package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

// history 命令：导出 / 导入 per-app 版本历史（version_history 表）。
//
// version_history 在每次 scan / inspect-list 时追加观察记录（不覆盖），
// 通过本命令可与远端快照来回合并：
//
// 用法：
//   hunter history -db hunter.db -export history.json     # 导出全量历史
//   hunter history -db hunter.db -import history.json     # 合并导入历史
func runHistory(args []string) {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	var (
		dbPath     string
		exportPath string
		importPath string
	)
	fs.StringVar(&dbPath, "db", "hunter.db", "SQLite database `path`")
	fs.StringVar(&exportPath, "export", "", "export full version history to `path`")
	fs.StringVar(&importPath, "import", "", "merge version history from `path`")
	fs.Parse(args)

	if dbPath == "" || (exportPath == "" && importPath == "") {
		fmt.Fprintln(os.Stderr, "usage: hunter history -db <path> [-export out.json] [-import in.json]")
		os.Exit(1)
	}

	db, err := OpenDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if exportPath != "" {
		recs, err := db.ExportHistory()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] export: %v\n", err)
			os.Exit(1)
		}
		doc := map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"observations": recs,
		}
		if err := writeJSON(exportPath, doc); err != nil {
			fmt.Fprintf(os.Stderr, "[error] write %s: %v\n", exportPath, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[history] exported %d records to %s\n", len(recs), exportPath)
	}

	if importPath != "" {
		data, err := os.ReadFile(importPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] read %s: %v\n", importPath, err)
			os.Exit(1)
		}
		var doc struct {
			Observations []HistoryRecord `json:"observations"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "[error] parse %s: %v\n", importPath, err)
			os.Exit(1)
		}
		n, err := db.ImportHistory(doc.Observations)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] import: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[history] merged %d records from %s\n", n, importPath)
	}
}