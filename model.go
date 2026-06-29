package main

import "time"

type Framework string

const (
	FrameworkElectron     Framework = "electron"
	FrameworkElectronFork Framework = "electron_fork"
	FrameworkQtWebEngine  Framework = "qt_webengine"
	FrameworkCEF          Framework = "cef"
)

const (
	MethodFrameworkPath = "framework_path"
	MethodBinaryStrings = "binary_strings"
	MethodElectronMap   = "electron_mapping"
	MethodNone          = "unknown"
)

type App struct {
	Name             string    `json:"app_name"`
	Path             string    `json:"app_path"`
	Framework        Framework `json:"framework"`
	FrameworkName    string    `json:"framework_name,omitempty"`
	ChromiumVersion  string    `json:"chromium_version,omitempty"`
	ElectronVersion  string    `json:"electron_version,omitempty"`
	ExtractionMethod string    `json:"extraction_method,omitempty"`
	BinaryPath       string    `json:"binary_path,omitempty"`
}

type ScanResult struct {
	Platform  string `json:"platform"`
	ScanTime  string `json:"scan_time"`
	Scope     string `json:"scope"`
	Total     int    `json:"total_apps"`
	WithCVER  int    `json:"with_chromium_version"`
	Apps      []App  `json:"apps"`
}

func newScanResult(apps []App, scope string) ScanResult {
	with := 0
	for _, a := range apps {
		if a.ChromiumVersion != "" {
			with++
		}
	}
	return ScanResult{
		Platform: "macos",
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		Scope:    scope,
		Total:    len(apps),
		WithCVER: with,
		Apps:     apps,
	}
}
