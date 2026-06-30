package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// risk 命令：将 hunter 数据库中检测到的 app × chromium-intel CVE 数据库匹配，
// 找出每个 app 受影响的 CVE，按优先级分类输出。
//
// 优先级：
//   CRITICAL  in_kev=True         CISA 确认在野利用
//   HIGH      in_the_wild=True    Google 确认在野利用
//   INFO      has bug_url/gerrit  公开了 patch 信息
//
// 版本匹配：app Chromium < CVE fixed version → 受影响
// 平台过滤：跳过 "on Android" / "on iOS" only 的 CVE（hunter 检测桌面 app）
// ---------------------------------------------------------------------------

// riskReportData 对应 chromium-intel/data/risk-report.json
type riskReportData struct {
	GeneratedAt string      `json:"generated_at"`
	Summary     riskSummary `json:"summary"`
	CVEs        []riskCVE   `json:"cves"`
}

type riskSummary struct {
	TotalCVEs int `json:"total_cves"`
	InKEV     int `json:"in_kev"`
	InTheWild int `json:"in_the_wild"`
}

type riskCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	CVSS         float64          `json:"cvss"`
	Description  string           `json:"description"`
	Versions     []string         `json:"versions"`
	BugID        string           `json:"bug_id"`
	BugURL       string           `json:"bug_url"`
	GerritURL    string           `json:"gerrit_url"`
	GerritSubj   string           `json:"gerrit_subject"`
	BlogURL      string           `json:"blog_url"`
	InKEV        bool             `json:"in_kev"`
	KEVDate      string           `json:"kev_date"`
	KEVDesc      string           `json:"kev_desc"`
	InTheWild    bool             `json:"in_the_wild"`
	Component    string           `json:"component"`
	CompType     string           `json:"component_type"`
	Exploitability riskExploitab  `json:"exploitability"`
}

type riskExploitab struct {
	Level  string `json:"level"`
	Label  string `json:"label"`
	Order  int    `json:"order"`
	Reason string `json:"reason"`
}

// appRisk 是单个 app 的匹配结果
type appRisk struct {
	AppName         string `json:"app_name"`
	AppVersion      string `json:"app_version"`
	Framework       string `json:"framework"`
	ChromiumVersion string `json:"chromium_version"`
	TotalCVEs       int    `json:"total_cves"`
	Critical        int    `json:"critical"`  // in_kev
	High            int    `json:"high"`      // in_the_wild
	HasPatch        int    `json:"has_patch"` // bug_url/gerrit
	TopCVEs         []matchedCVE `json:"top_cves"`
}

type matchedCVE struct {
	ID          string `json:"id"`
	Priority    string `json:"priority"` // CRITICAL / HIGH / PATCH / OTHER
	InKEV       bool   `json:"in_kev"`
	InTheWild   bool   `json:"in_the_wild"`
	HasPatch    bool   `json:"has_patch"`
	Component   string `json:"component"`
	Published   string `json:"published"`
	Description string `json:"description"`
	FixedVer    string `json:"fixed_version"`
	BlogURL     string `json:"blog_url,omitempty"`
	BugURL      string `json:"bug_url,omitempty"`
}

var chromiumVerRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.(\d+)`)
var priorToRe = regexp.MustCompile(`(?i)(?:prior to|before)\s+(\d+\.\d+\.\d+\.\d+)`)
var androidOnlyRe = regexp.MustCompile(`(?i)on android`)
var iosOnlyRe = regexp.MustCompile(`(?i)on ios|on iphone`)

// compareChromiumVer 比较 a 和 b (格式 X.Y.Z.W)
// 返回 -1 if a<b, 0 if a==b, 1 if a>b
func compareChromiumVer(a, b string) int {
	ma := chromiumVerRe.FindStringSubmatch(a)
	mb := chromiumVerRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 4; i++ {
		ai := atoiSafe(ma[i])
		bi := atoiSafe(mb[i])
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// getFixedVersion 从 CVE 提取 fixed version（最小版本号 = 最先修复的）
func getFixedVersion(c *riskCVE) string {
	// 方法 1: versions[] 已是纯版本号 (如 "149.0.7827.201")
	if len(c.Versions) > 0 {
		v := c.Versions[0]
		if chromiumVerRe.MatchString(v) {
			return chromiumVerRe.FindString(v)
		}
		// versions[] 存了描述文本，需要提取
		return extractFirstVersion(v)
	}
	// 方法 2: 从描述提取 "prior to X.Y.Z.W"
	return extractFirstVersion(c.Description)
}

var anyVerRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)

// extractFirstVersion 从文本中提取第一个 Chromium 版本号
func extractFirstVersion(text string) string {
	// 优先匹配 "prior to X.Y.Z.W"
	if m := priorToRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	// 回退到任意 X.Y.Z.W
	if m := anyVerRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// isDesktopCVE 判断是否影响桌面平台
func isDesktopCVE(c *riskCVE) bool {
	desc := c.Description
	// 如果明确说是 Android/iOS only，跳过
	if androidOnlyRe.MatchString(desc) && !strings.Contains(strings.ToLower(desc), "desktop") &&
		!strings.Contains(strings.ToLower(desc), "on windows") &&
		!strings.Contains(strings.ToLower(desc), "on mac") &&
		!strings.Contains(strings.ToLower(desc), "on linux") {
		return false
	}
	if iosOnlyRe.MatchString(desc) && !strings.Contains(strings.ToLower(desc), "desktop") {
		return false
	}
	return true
}

func runRisk(args []string) {
	fs := flag.NewFlagSet("risk", flag.ExitOnError)
	var (
		dbPath     string
		riskReport string
		jsonOut    string
		onlyCrit   bool
		appFilter  string
	)
	fs.StringVar(&dbPath, "db", "hunter.db", "hunter SQLite database")
	fs.StringVar(&riskReport, "risk-report", "", "path to chromium-intel risk-report.json (required)")
	fs.StringVar(&jsonOut, "json", "", "write JSON report to path")
	fs.BoolVar(&onlyCrit, "critical-only", false, "only show CRITICAL (in_kev) + HIGH (in_the_wild)")
	fs.StringVar(&appFilter, "name", "", "filter by app name (fuzzy)")
	fs.Parse(args)

	if riskReport == "" {
		fmt.Fprintln(os.Stderr, "usage: hunter risk -risk-report <path> -db <path>")
		fmt.Fprintln(os.Stderr, "  -risk-report is required (chromium-intel/data/risk-report.json)")
		os.Exit(1)
	}

	// 加载 CVE 数据
	data, err := os.ReadFile(riskReport)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] read risk-report: %v\n", err)
		os.Exit(1)
	}
	var rr riskReportData
	if err := json.Unmarshal(data, &rr); err != nil {
		fmt.Fprintf(os.Stderr, "[error] parse risk-report: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[risk] loaded %d CVEs (in_kev=%d, in_the_wild=%d)\n",
		len(rr.CVEs), rr.Summary.InKEV, rr.Summary.InTheWild)

	// 加载 app 数据
	db, err := OpenDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] open db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	query := `SELECT name, COALESCE(app_version,''), framework, COALESCE(chromium_version,'')
	          FROM latest_apps WHERE chromium_version IS NOT NULL AND chromium_version != ''`
	rows, err := db.conn.Query(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] query: %v\n", err)
		os.Exit(1)
	}
	var apps []struct {
		name, ver, fw, cv string
	}
	for rows.Next() {
		var a struct{ name, ver, fw, cv string }
		rows.Scan(&a.name, &a.ver, &a.fw, &a.cv)
		if appFilter != "" && !strings.Contains(strings.ToLower(a.name), strings.ToLower(appFilter)) {
			continue
		}
		apps = append(apps, a)
	}
	rows.Close()
	fmt.Fprintf(os.Stderr, "[risk] %d apps to check\n", len(apps))

	// 预处理 CVE：过滤桌面平台 + 提取 fixed version
	type cveWithFixed struct {
		cve   *riskCVE
		fixed string
	}
	var desktopCVEs []cveWithFixed
	for i := range rr.CVEs {
		c := &rr.CVEs[i]
		if !isDesktopCVE(c) {
			continue
		}
		fv := getFixedVersion(c)
		if fv == "" {
			continue // 无法确定 fixed version，跳过
		}
		desktopCVEs = append(desktopCVEs, cveWithFixed{c, fv})
	}
	// 按 fixed version 排序（降序），这样最新版本在前
	sort.Slice(desktopCVEs, func(i, j int) bool {
		return compareChromiumVer(desktopCVEs[i].fixed, desktopCVEs[j].fixed) > 0
	})

	// 匹配
	var results []appRisk
	var allMatched []matchedCVE // 全局统计

	for _, app := range apps {
		ar := appRisk{
			AppName:         app.name,
			AppVersion:      app.ver,
			Framework:       app.fw,
			ChromiumVersion: app.cv,
		}

		for _, cf := range desktopCVEs {
			// app version < fixed version → 受影响
			if compareChromiumVer(app.cv, cf.fixed) < 0 {
				mc := classifyCVE(cf.cve, cf.fixed)
				ar.TotalCVEs++
				switch mc.Priority {
				case "CRITICAL":
					ar.Critical++
				case "HIGH":
					ar.High++
				case "PATCH":
					ar.HasPatch++
				}
				// 只保留高危 CVE 到 TopCVEs
				if mc.Priority == "CRITICAL" || mc.Priority == "HIGH" {
					ar.TopCVEs = append(ar.TopCVEs, mc)
					allMatched = append(allMatched, mc)
				} else if !onlyCrit && mc.Priority == "PATCH" && len(ar.TopCVEs) < 10 {
					ar.TopCVEs = append(ar.TopCVEs, mc)
				}
			}
		}

		// 限制 TopCVEs 数量
		if len(ar.TopCVEs) > 20 {
			ar.TopCVEs = ar.TopCVEs[:20]
		}

		results = append(results, ar)
	}

	// 排序：先按 Critical 降序，再 High，再 Total
	sort.Slice(results, func(i, j int) bool {
		if results[i].Critical != results[j].Critical {
			return results[i].Critical > results[j].Critical
		}
		if results[i].High != results[j].High {
			return results[i].High > results[j].High
		}
		return results[i].TotalCVEs > results[j].TotalCVEs
	})

	// 打印结果
	printRiskTable(results, onlyCrit)

	// 全局统计
	fmt.Printf("\n===== SUMMARY =====\n")
	totalCrit := 0
	totalHigh := 0
	appsWitRisk := 0
	for _, r := range results {
		if r.Critical > 0 || r.High > 0 {
			appsWitRisk++
		}
		totalCrit += r.Critical
		totalHigh += r.High
	}
	fmt.Printf("Apps checked:        %d\n", len(results))
	fmt.Printf("Apps with CRITICAL:  %d (CISA KEV exploitation)\n", countBy(results, func(r appRisk) bool { return r.Critical > 0 }))
	fmt.Printf("Apps with HIGH:      %d (Google in-the-wild)\n", countBy(results, func(r appRisk) bool { return r.High > 0 }))
	fmt.Printf("Total CRITICAL CVEs: %d\n", totalCrit)
	fmt.Printf("Total HIGH CVEs:     %d\n", totalHigh)

	// JSON 输出
	if jsonOut != "" {
		writeJSON(jsonOut, results)
		fmt.Fprintf(os.Stderr, "[report] JSON saved to %s\n", jsonOut)
	}
}

func countBy(results []appRisk, pred func(appRisk) bool) int {
	n := 0
	for _, r := range results {
		if pred(r) {
			n++
		}
	}
	return n
}

func classifyCVE(c *riskCVE, fixedVer string) matchedCVE {
	mc := matchedCVE{
		ID:          c.ID,
		InKEV:       c.InKEV,
		InTheWild:   c.InTheWild,
		Component:   c.Component,
		Published:   c.Published[:10],
		Description: truncate(c.Description, 120),
		FixedVer:    fixedVer,
		BlogURL:     c.BlogURL,
		BugURL:      c.BugURL,
	}
	if c.BugURL != "" || c.GerritURL != "" {
		mc.HasPatch = true
	}

	switch {
	case c.InKEV:
		mc.Priority = "CRITICAL"
	case c.InTheWild:
		mc.Priority = "HIGH"
	case mc.HasPatch:
		mc.Priority = "PATCH"
	default:
		mc.Priority = "OTHER"
	}
	return mc
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func printRiskTable(results []appRisk, onlyCrit bool) {
	// 表头
	fmt.Printf("\n%-24s %-14s %-14s %8s %8s %8s\n",
		"APP", "CHROMIUM", "FRAMEWORK", "CRIT", "HIGH", "TOTAL")
	fmt.Printf("%s\n", strings.Repeat("-", 80))

	for _, r := range results {
		if onlyCrit && r.Critical == 0 && r.High == 0 {
			continue
		}
		cv := r.ChromiumVersion
		if len(cv) > 14 {
			cv = cv[:14]
		}
		fw := r.Framework
		if len(fw) > 14 {
			fw = fw[:14]
		}
		fmt.Printf("%-24s %-14s %-14s %8d %8d %8d\n",
			r.AppName[:min(24, len(r.AppName))], cv, fw,
			r.Critical, r.High, r.TotalCVEs)
	}

	// 打印高危 CVE 详情
	fmt.Printf("\n===== HIGH-RISK CVE DETAILS =====\n\n")
	for _, r := range results {
		if r.Critical == 0 && r.High == 0 {
			continue
		}
		fmt.Printf("■ %s (Chromium %s)\n", r.AppName, r.ChromiumVersion)
		for _, cve := range r.TopCVEs {
			if cve.Priority != "CRITICAL" && cve.Priority != "HIGH" {
				continue
			}
			badges := ""
			if cve.InKEV {
				badges += " [CISA-KEV]"
			}
			if cve.InTheWild {
				badges += " [IN-THE-WILD]"
			}
			fmt.Printf("  %-16s %s %s\n", cve.ID, cve.Priority, badges)
			fmt.Printf("  %s\n", cve.Description)
			fmt.Printf("  Component: %s | Fixed: %s | Published: %s\n",
				cve.Component, cve.FixedVer, cve.Published)
			if cve.BlogURL != "" {
				fmt.Printf("  Blog: %s\n", cve.BlogURL)
			}
			fmt.Println()
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
