package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const osvQueryAPI = "https://api.osv.dev/v1/query"

// ---------------------------------------------------------------------------
// OSV API 请求/响应结构
// ---------------------------------------------------------------------------

type osvQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string       `json:"id"`
	Summary   string       `json:"summary"`
	Details   string       `json:"details"`
	Aliases   []string     `json:"aliases"`
	Severity  []osvSeverity `json:"severity"`
	Published string       `json:"published"`
	Modified  string       `json:"modified"`
	Affected  []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// ---------------------------------------------------------------------------
// 输出结构
// ---------------------------------------------------------------------------

type osvCVEEntry struct {
	ID          string   `json:"id"`
	CVE         string   `json:"cve,omitempty"`
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	CVSSScore   string   `json:"cvss_score,omitempty"`
	Published   string   `json:"published,omitempty"`
	FixVersions []string `json:"fix_versions,omitempty"`
}

type osvAppResult struct {
	AppName         string        `json:"app_name"`
	AppVersion      string        `json:"app_version,omitempty"`
	ElectronVersion string        `json:"electron_version"`
	TotalCVEs       int           `json:"total_cves"`
	CVEs            []osvCVEEntry `json:"cves"`
	Error           string        `json:"error,omitempty"`
}

type osvReport struct {
	Generator       string            `json:"generator"`
	ScanTime        string            `json:"scan_time"`
	Source          string            `json:"source,omitempty"`
	TotalApps       int               `json:"total_apps"`
	WithElectron    int               `json:"with_electron_version"`
	MissingVersion  int               `json:"missing_electron_version"`
	Checked         int               `json:"checked"`
	Failed          int               `json:"failed"`
	WithCVEs        int               `json:"with_cves"`
	TotalCVEs       int               `json:"total_cves"`
	SeverityCounts  map[string]int    `json:"severity_counts"`
	Apps            []osvAppResult    `json:"apps"`
}

// ---------------------------------------------------------------------------
// 命令入口
// ---------------------------------------------------------------------------

func runOSVCheck(args []string) {
	fs := flag.NewFlagSet("osv-check", flag.ExitOnError)
	var (
		input        string
		output       string
		concurrency  int
		timeout      time.Duration
		onlyElectron bool
	)
	fs.StringVar(&input, "input", "", "path to scan/inspect JSON with apps (required)")
	fs.StringVar(&output, "output", "", "path to write OSV results (default: stdout)")
	fs.IntVar(&concurrency, "concurrency", 8, "number of concurrent OSV queries")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "per-query timeout")
	fs.BoolVar(&onlyElectron, "electron-only", true, "only query apps with electron_version")
	fs.Parse(args)

	if input == "" {
		fmt.Fprintln(os.Stderr, "usage: hunter osv-check -input <scan.json> [-output <osv.json>] [-concurrency 8]")
		os.Exit(1)
	}

	var sr ScanResult
	data, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(data, &sr); err != nil {
		fmt.Fprintf(os.Stderr, "[error] parse %s: %v\n", input, err)
		os.Exit(1)
	}

	// 只对 Electron 系应用查询（OSV 覆盖 Electron 框架层）
	var targets []App
	missing := 0
	for _, a := range sr.Apps {
		if !a.ElectronFramework() {
			continue
		}
		if a.ElectronVersion == "" {
			missing++
			continue
		}
		targets = append(targets, a)
	}

	report := osvReport{
		Generator:      "hunter osv-check " + version,
		ScanTime:       time.Now().UTC().Format(time.RFC3339),
		Source:         input,
		TotalApps:      len(sr.Apps),
		WithElectron:   len(targets) + missing,
		MissingVersion: missing,
		SeverityCounts: map[string]int{},
	}

	// 并发查询
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	results := make([]osvAppResult, len(targets))
	for i, app := range targets {
		wg.Add(1)
		go func(i int, app App) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := osvAppResult{
				AppName:         app.Name,
				AppVersion:      app.AppVersion,
				ElectronVersion: app.ElectronVersion,
				CVEs:            []osvCVEEntry{},
			}
			vulns, err := osvQueryElectron(app.ElectronVersion, timeout)
			if err != nil {
				res.Error = err.Error()
			} else {
				res.CVEs = buildCVEEntries(app.ElectronVersion, vulns)
				res.TotalCVEs = len(res.CVEs)
			}
			results[i] = res
		}(i, app)
	}
	wg.Wait()

	// 汇总
	for _, r := range results {
		report.Apps = append(report.Apps, r)
		if r.Error != "" {
			report.Failed++
			continue
		}
		report.Checked++
		if r.TotalCVEs > 0 {
			report.WithCVEs++
			report.TotalCVEs += r.TotalCVEs
			for _, c := range r.CVEs {
				report.SeverityCounts[c.Severity]++
			}
		}
	}
	if report.Apps == nil {
		report.Apps = []osvAppResult{}
	}
	if !onlyElectron && len(report.SeverityCounts) == 0 {
		report.SeverityCounts = map[string]int{}
	}

	if output != "" {
		if err := writeJSON(output, report); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[report] OSV results saved to %s\n", output)
	} else {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
	}

	fmt.Fprintf(os.Stderr, "[osv] %d/%d app(s) with electron_version, %d with CVEs (%d total), %d failed\n",
		report.Checked, report.WithElectron, report.WithCVEs, report.TotalCVEs, report.Failed)
}

// ElectronPackage 报告该 App 是否为 Electron 系（可查询 OSV）
func (a *App) ElectronFramework() bool {
	return a.Framework == FrameworkElectron || a.Framework == FrameworkElectronFork
}

// ---------------------------------------------------------------------------
// OSV 查询
// ---------------------------------------------------------------------------

func osvQueryElectron(version string, timeout time.Duration) ([]osvVuln, error) {
	body, err := json.Marshal(osvQueryRequest{
		Package: osvPackage{Ecosystem: "npm", Name: "electron"},
		Version: version,
	})
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(osvQueryAPI, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osv query: HTTP %d", resp.StatusCode)
	}

	var out osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}
	return out.Vulns, nil
}

// ---------------------------------------------------------------------------
// 受影响判定与输出构建
// ---------------------------------------------------------------------------

// buildCVEEntries 过滤出真正影响 version 的 advisory，并提取修复版本
func buildCVEEntries(version string, vulns []osvVuln) []osvCVEEntry {
	entries := []osvCVEEntry{}
	for _, v := range vulns {
		fixes := affectedFixes(version, v)
		if fixes == nil {
			continue // 该 advisory 不影响此版本
		}
		sev, score := vulnSeverity(v)
		e := osvCVEEntry{
			ID:        v.ID,
			Summary:   v.Summary,
			Severity:  sev,
			CVSSScore: score,
			Published: v.Published,
		}
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				e.CVE = alias
				break
			}
		}
		if len(fixes) > 0 {
			e.FixVersions = fixes
		}
		entries = append(entries, e)
	}
	// 按严重级别倒序，同级别按 ID
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Severity != entries[j].Severity {
			return severityRank(entries[i].Severity) > severityRank(entries[j].Severity)
		}
		return entries[i].ID < entries[j].ID
	})
	return entries
}

// affectedFixes 判定 version 是否在 affected range 内；
// 命中返回可用的修复版本列表（nil 表示不受影响）
func affectedFixes(version string, v osvVuln) []string {
	fixSet := map[string]bool{}
	affected := false
	for _, a := range v.Affected {
		if a.Package.Name != "electron" || a.Package.Ecosystem != "npm" {
			continue
		}
		for _, r := range a.Ranges {
			introduced := ""
			for _, ev := range r.Events {
				switch {
				case ev.Introduced != "":
					introduced = ev.Introduced
				case ev.Fixed != "":
					if introduced != "" && compareSemver(version, introduced) >= 0 && compareSemver(version, ev.Fixed) < 0 {
						affected = true
						fixSet[ev.Fixed] = true
					}
					introduced = ""
				case ev.LastAffected != "":
					if introduced != "" && compareSemver(version, introduced) >= 0 && compareSemver(version, ev.LastAffected) <= 0 {
						affected = true
					}
					introduced = ""
				}
			}
		}
	}
	if !affected {
		return nil
	}
	fixes := make([]string, 0, len(fixSet))
	for f := range fixSet {
		if compareSemver(f, version) > 0 {
			fixes = append(fixes, f)
		}
	}
	sort.Slice(fixes, func(i, j int) bool { return compareSemver(fixes[i], fixes[j]) < 0 })
	return fixes
}

// vulnSeverity 从 CVSS vector 计算 base score 并映射级别
func vulnSeverity(v osvVuln) (string, string) {
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		if score, ok := parseCVSSBaseScore(s.Score); ok {
			return cvssLevel(score), fmt.Sprintf("%.1f", score)
		}
	}
	return "unknown", ""
}

func cvssLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// CVSS 3.x base score 计算（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 格式）
// ---------------------------------------------------------------------------

func parseCVSSBaseScore(vector string) (float64, bool) {
	metrics := map[string]string{}
	for _, p := range strings.Split(vector, "/") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	need := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, k := range need {
		if metrics[k] == "" {
			return 0, false
		}
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
	if metrics["S"] == "U" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[metrics["PR"]]
	}
	ci := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[metrics["C"]]
	ii := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[metrics["I"]]
	ai := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[metrics["A"]]

	iss := 1 - (1-ci)*(1-ii)*(1-ai)
	var impact float64
	if metrics["S"] == "U" {
		impact = 6.42 * iss
	} else {
		if iss-0.02 <= 0 {
			return 0, false
		}
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exp := 8.22 * av * ac * pr * ui
	var score float64
	if metrics["S"] == "U" {
		score = exp + impact
	} else {
		score = 1.08 * (exp + impact)
	}
	if score <= 0 {
		return 0, true
	}
	return math.Round(math.Min(score, 10)*10) / 10, true
}

// ---------------------------------------------------------------------------
// semver 比较
// ---------------------------------------------------------------------------

func compareSemver(a, b string) int {
	pa, _ := parseSemver(a)
	pb, _ := parseSemver(b)
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseSemver(s string) ([4]int, error) {
	var out [4]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	for i := 0; i < len(parts) && i < 4; i++ {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil {
			return out, err
		}
		out[i] = n
	}
	return out, nil
}