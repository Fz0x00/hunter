package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// catalog 命令：查询统一版本目录（app_catalog 表）
//
// 目录把三份数据拉通为每 app 一行：
//   - 下载地址层：url/github/release_feed/version_api（来自 apps.json）
//   - 解析签名层：resolved_signature/last_checked/last_changed（version-check 写入）
//   - 实测版本层：app_version/electron_version/chromium_version/verified_at（inspect-list 回填）
//
// 用法：
//   hunter catalog -db hunter.db                       # 全量目录
//   hunter catalog -db hunter.db -name Lark            # 按名过滤
//   hunter catalog -db hunter.db -stale                # 只有配置无实测/签名过期
//   hunter catalog -db hunter.db -json                 # JSON 输出
func runCatalog(args []string) {
	fs := flag.NewFlagSet("catalog", flag.ExitOnError)
	var (
		dbPath  string
		name    string
		stale   bool
		jsonOut bool
		output  string
	)
	fs.StringVar(&dbPath, "db", "hunter.db", "SQLite database path")
	fs.StringVar(&name, "name", "", "filter by app name (fuzzy match)")
	fs.BoolVar(&stale, "stale", false, "only apps missing verified versions or changed since last verified")
	fs.BoolVar(&jsonOut, "json", false, "output as JSON")
	fs.StringVar(&output, "output", "", "write JSON report to path (implies -json)")
	fs.Parse(args)

	if dbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: hunter catalog -db <path> [filters]")
		os.Exit(1)
	}

	db, err := OpenDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.QueryCatalog(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] catalog: %v\n", err)
		os.Exit(1)
	}

	if stale {
		var fresh []CatalogRow
		for _, r := range rows {
			if r.ChromiumVersion == "" || r.ResolvedSignature == "" {
				fresh = append(fresh, r)
				continue
			}
			// 签名变更晚于实测时间 → 需要重新 inspect
			if r.LastChanged != "" && (r.VerifiedAt == "" || r.LastChanged > r.VerifiedAt) {
				fresh = append(fresh, r)
			}
		}
		rows = fresh
	}

	if output != "" || jsonOut {
		body, _ := json.MarshalIndent(map[string]any{
			"generator": "hunter catalog " + version,
			"total":     len(rows),
			"apps":      rows,
		}, "", "  ")
		if output != "" {
			if err := writeJSON(output, map[string]any{
				"generator": "hunter catalog " + version,
				"total":     len(rows),
				"apps":      rows,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "[error] %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "[report] catalog saved to %s (%d app(s))\n", output, len(rows))
			return
		}
		fmt.Println(string(body))
		return
	}

	printCatalogTable(rows)
}

func printCatalogTable(rows []CatalogRow) {
	if len(rows) == 0 {
		fmt.Println("(no results)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tSIGNATURE\tAPP VER\tCHROMIUM\tELECTRON\tCHECKED\tVERIFIED")
	fmt.Fprintln(w, strings.Repeat("-", 22)+"\t"+strings.Repeat("-", 16)+"\t"+strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 16)+"\t"+strings.Repeat("-", 9)+"\t"+strings.Repeat("-", 19)+"\t"+strings.Repeat("-", 19))
	for _, r := range rows {
		sig := r.ResolvedSignature
		if sig == "" {
			sig = "?"
		}
		appVer := orDash(r.AppVersion)
		chrome := orDash(r.ChromiumVersion)
		electron := orDash(r.ElectronVersion)
		checked := r.LastChecked
		if len(checked) >= 10 {
			checked = checked[:10]
		}
		verified := r.VerifiedAt
		if len(verified) >= 10 {
			verified = verified[:10]
		}
		if verified == "" {
			verified = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			trunc(r.AppName, 22), trunc(sig, 16), appVer, chrome, electron, checked, verified)
	}
	w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}