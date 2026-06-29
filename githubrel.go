package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func resolveGitHubRelease(repo, assetPattern string) (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hunter/"+version)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API %d for %s", resp.StatusCode, repo)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", "", err
	}

	re, err := regexp.Compile(assetPattern)
	if err != nil {
		return "", "", fmt.Errorf("bad pattern %q: %w", assetPattern, err)
	}

	for _, asset := range rel.Assets {
		if re.MatchString(asset.Name) {
			return asset.BrowserDownloadURL, rel.TagName, nil
		}
	}
	return "", "", fmt.Errorf("no asset matching %q in %s@%s", assetPattern, repo, rel.TagName)
}
