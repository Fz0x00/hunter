package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type AppEntry struct {
	Name         string `json:"name"`
	Publisher    string `json:"publisher,omitempty"`
	URL          string `json:"url,omitempty"`
	GitHub       string `json:"github,omitempty"`
	AssetPattern string `json:"asset_pattern,omitempty"`
	ReleaseFeed  string `json:"release_feed,omitempty"`
	Homepage     string `json:"homepage,omitempty"`
}

type AppRegistry struct {
	Apps []AppEntry `json:"apps"`
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

func (e *AppEntry) resolveDownloadURL() (string, string, error) {
	if e.URL != "" {
		return e.URL, "", nil
	}
	if e.ReleaseFeed != "" {
		return resolveReleaseFeed(e.ReleaseFeed)
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
