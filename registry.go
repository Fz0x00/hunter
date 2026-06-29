package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type AppEntry struct {
	Name         string `json:"name"`
	Publisher    string `json:"publisher,omitempty"`
	URL          string `json:"url,omitempty"`
	GitHub       string `json:"github,omitempty"`
	AssetPattern string `json:"asset_pattern,omitempty"`
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

func (e *AppEntry) resolveDownloadURL() (string, string, error) {
	if e.URL != "" {
		return e.URL, "", nil
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
