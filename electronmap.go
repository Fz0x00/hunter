package main

import (
	"encoding/json"
	"os"
	"strings"
)

type ElectronMap struct {
	entries map[string]string
}

type electronMapFile struct {
	GeneratedAt     string `json:"generated_at"`
	ElectronVersions []struct {
		Electron string `json:"electron"`
		Chromium string `json:"chromium"`
	} `json:"electron_versions"`
}

func LoadElectronMap(path string) (*ElectronMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f electronMapFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	em := &ElectronMap{entries: map[string]string{}}
	for _, e := range f.ElectronVersions {
		em.entries[e.Electron] = e.Chromium
	}
	return em, nil
}

func (em *ElectronMap) LookupChromium(electronVersion string) (string, bool) {
	if v, ok := em.entries[electronVersion]; ok {
		return v, true
	}
	parts := strings.Split(electronVersion, ".")
	if len(parts) >= 2 {
		majorMinor := parts[0] + "." + parts[1] + ".0"
		if v, ok := em.entries[majorMinor]; ok {
			return v, true
		}
	}
	return "", false
}
