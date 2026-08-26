package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type AppEntry struct {
	Name         string `json:"name"`
	Publisher    string `json:"publisher,omitempty"`
	URL          string `json:"url,omitempty"`
	GitHub       string `json:"github,omitempty"`
	AssetPattern string `json:"asset_pattern,omitempty"`
	ReleaseFeed  string `json:"release_feed,omitempty"`
	VersionAPI   string `json:"version_api,omitempty"` // GET 返回 JSON/文本中含版本
	Cask         string `json:"cask,omitempty"`        // Homebrew cask token（formulae.brew.sh 元数据）
	Homepage     string `json:"homepage,omitempty"`
	Platform     string `json:"platform,omitempty"` // "macos" = needs hdiutil; empty/"any" = any OS
	Dynamic      bool   `json:"dynamic,omitempty"`  // true = URL from dynamic-urls.json
}

type AppRegistry struct {
	Apps []AppEntry `json:"apps"`
}

// dynamicURLMap holds URLs collected by the playwright URL collector
// (scripts/collect_urls.py → dynamic-urls.json). Used for apps whose
// download pages are JS-rendered and cannot be resolved statically.
type dynamicURLFile struct {
	Updated string            `json:"updated"`
	URLs    map[string]string `json:"urls"`
}

var dynamicURLs map[string]string

// loadDynamicURLs loads dynamic-urls.json from the given path (optional).
// If path is empty or file missing, dynamicURLs stays nil (no-op).
func loadDynamicURLs(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var f dynamicURLFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	dynamicURLs = f.URLs
}

func loadRegistry(path string) (*AppRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var reg AppRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

// platformMatches 判断 app 是否满足平台过滤（共享给 version-check 与 inspect-list）：
// 空过滤 = 全部；"macos" = 仅 macOS 专属应用；"linux" = 非 macOS 应用；"any" = 全部
func platformMatches(e AppEntry, filter string) bool {
	if filter == "" {
		return true
	}
	if filter == "macos" {
		return e.Platform == "macos"
	}
	if filter == "linux" {
		return e.Platform != "macos"
	}
	return true // "any"
}

// Squirrel release feed (Electron auto-update format)
// { "releases": [ {"updateTo": {"url": "...", "version": "..."}}, ... ] }
type squirrelFeed struct {
	Releases []struct {
		UpdateTo struct {
			URL     string `json:"url"`
			Version string `json:"version"`
		} `json:"updateTo"`
	} `json:"releases"`
}

func resolveReleaseFeed(feedURL string) (string, string, error) {
	req, err := http.NewRequest("GET", feedURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "hunter/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("release feed HTTP %d for %s", resp.StatusCode, feedURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	var feed squirrelFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return "", "", fmt.Errorf("parse release feed: %w", err)
	}
	if len(feed.Releases) == 0 {
		return "", "", fmt.Errorf("no releases in feed %s", feedURL)
	}
	// 取第一个（最新）release
	rel := feed.Releases[0].UpdateTo
	urlStr := rel.URL
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		// 相对 URL，用 feed URL 的 base 解析
		feedURLParsed, _ := url.Parse(feedURL)
		if feedURLParsed != nil {
			relURL, err := feedURLParsed.Parse(urlStr)
			if err == nil {
				urlStr = relURL.String()
			}
		}
	}
	return urlStr, rel.Version, nil
}

// Homebrew cask 元数据（https://formulae.brew.sh/api/cask/{token}.json）
// version 可能是复合值（如 "8.5.0,57546446"）——原样返回，保证签名稳定性
type caskMeta struct {
	Token   string `json:"token"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// resolveCask 查询 Homebrew cask API，返回官方下载 URL + 当前版本。
// 版本和地址由 Homebrew 社区维护，一次配置即可持续跟踪版本变更。
func resolveCask(token string) (string, string, error) {
	apiURL := "https://formulae.brew.sh/api/cask/" + url.PathEscape(token) + ".json"
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "hunter/"+version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("cask HTTP %d for %s", resp.StatusCode, token)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	var meta caskMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", "", fmt.Errorf("parse cask %s: %w", token, err)
	}
	if meta.URL == "" || meta.Version == "" {
		return "", "", fmt.Errorf("cask %s: empty url/version", token)
	}
	return meta.URL, meta.Version, nil
}

func (e *AppEntry) resolveDownloadURL() (string, string, error) {
	// Dynamic apps: URL from playwright collector (dynamic-urls.json)
	if e.Dynamic && dynamicURLs != nil {
		if u, ok := dynamicURLs[e.Name]; ok && u != "" {
			return u, "", nil
		}
	}
	if e.URL != "" {
		return e.URL, "", nil
	}
	if e.ReleaseFeed != "" {
		return resolveReleaseFeed(e.ReleaseFeed)
	}
	if e.Cask != "" {
		return resolveCask(e.Cask)
	}
	if e.GitHub != "" {
		pattern := e.AssetPattern
		if pattern == "" {
			pattern = `(?i)\.dmg$|darwin.*\.zip$|mac.*\.zip$|osx.*\.zip$`
		}
		return resolveGitHubRelease(e.GitHub, pattern)
	}
	return "", "", fmt.Errorf("no url or github for %s", e.Name)
}

// resolveVersionAPI GET 一个 JSON/文本版本 API，提取版本字符串。
// 支持格式：{"version":"1.2.3"}、{"productVersion":"1.2.3"}、裸 semver 文本。
func resolveVersionAPI(apiURL string) string {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "hunter/"+version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	// 提取 JSON 字段：优先 productVersion / tag_name，其次 version；
	// 且优先语义版本（避免 VS Code 的 version 是 commit hash 等）
	best := ""
	for _, m := range jsonVersionRe.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		key, val := string(m[1]), string(m[2])
		if val == "" {
			continue
		}
		isSemver := semverAnywhereRe.MatchString(val)
		if isSemver {
			if key == "productVersion" || key == "tag_name" || best == "" {
				return val
			}
			if best == "" {
				best = val
			}
		} else if best == "" && (key == "productVersion" || key == "tag_name") {
			best = val
		}
	}
	if best != "" {
		return best
	}
	// 兜底：文本中的第一个 semver
	if m := semverAnywhereRe.FindSubmatch(body); len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

var (
	jsonVersionRe    = regexp.MustCompile(`"(productVersion|version|tag_name)"\s*:\s*"([^"]+)"`)
	semverAnywhereRe = regexp.MustCompile(`\b(v?)(\d+\.\d+(?:\.\d+){0,2})\b`)
)

// resolveURLVersion 跟踪重定向并从最终 URL 提取版本。用于 fixed/latest URL 型 app
// （如 discord.com/api/download、updates.signal.org/desktop/latest）：
// 这些端点 3xx 到带版本的 CDN URL，HEAD 成本远低于下载安装包。
// 提取失败返回 ""（调用方 fallback 到原始 URL 签名）。
func resolveURLVersion(rawURL string) string {
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "hunter/"+version)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	finalURL := rawURL
	if resp != nil {
		resp.Body.Close()
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
	}
	return extractVersionToken(finalURL)
}

// versionTokenRe 提取 URL 中的语义版本或纯数字 build 号。
var (
	versionTokenRe  = regexp.MustCompile(`(?i)(?:^|/)(?:v|version[_-]?)?(\d+\.\d+(?:\.\d+){0,2})(?:[^0-9.]|$)`)
	buildTokenRe    = regexp.MustCompile(`(?i)(?:^|/)(\d{5,})(?:/|\.|$)`)
	metaPathSegment = regexp.MustCompile(`(?i)latest|stable|beta|canary|dev|downloads?|releases|versions|update|arch|arm|x64|x86|darwin|mac|macos|osx|universal|win|windows|linux`)
)

func extractVersionToken(u string) string {
	// 1) 语义版本：取最后一个出现（重定向终点的 URL 通常带版本）
	all := versionTokenRe.FindAllStringSubmatch(u, -1)
	for i := len(all) - 1; i >= 0; i-- {
		if tok := all[i][1]; tok != "" && !metaPathSegment.MatchString(tok) {
			return tok
		}
	}
	// 2) 兜底：≥5 位纯数字 build 号（如 Discord CDN 的 build id）；
	//    排除 20YYMMDD 日期形态
	all = buildTokenRe.FindAllStringSubmatch(u, -1)
	for i := len(all) - 1; i >= 0; i-- {
		if tok := all[i][1]; tok != "" && !dateLikeRe.MatchString(tok) {
			return tok
		}
	}
	return ""
}

var dateLikeRe = regexp.MustCompile(`^20\d{6}$`)
