package main

import (
	"os"
	"path/filepath"
	"strings"
)

func defaultScanPaths() []string {
	var paths []string
	paths = append(paths, "/Applications")
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, "Applications"))
	}
	return paths
}

func discoverApps(roots []string) []App {
	var apps []App
	seen := map[string]bool{}

	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			appPath := filepath.Join(root, entry.Name())
			if seen[appPath] {
				continue
			}
			app, ok := inspectApp(appPath)
			if ok {
				seen[appPath] = true
				apps = append(apps, app)
			}
		}
	}
	return apps
}

func inspectApp(appPath string) (App, bool) {
	if isKnownBrowser(appPath) {
		return App{}, false
	}

	frameworksDir := filepath.Join(appPath, "Contents", "Frameworks")
	entries, err := os.ReadDir(frameworksDir)
	if err != nil {
		return App{}, false
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "Electron Framework.framework" {
			return App{
				Name:          appNameFromPath(appPath),
				Path:          appPath,
				Framework:     FrameworkElectron,
				FrameworkName: "Electron Framework",
			}, true
		}
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".framework") {
			continue
		}
		if isKnownNonFramework(name) {
			continue
		}
		if hasElectronHelpers(frameworksDir, name) {
			fwName := strings.TrimSuffix(name, ".framework")
			return App{
				Name:          appNameFromPath(appPath),
				Path:          appPath,
				Framework:     FrameworkElectronFork,
				FrameworkName: fwName,
			}, true
		}
	}

	return App{}, false
}

func isKnownNonFramework(name string) bool {
	switch name {
	case "Electron Framework.framework",
		"Squirrel.framework",
		"ReactiveCocoa.framework",
		"Mantle.framework",
		"Sparkle.framework",
		"Growl.framework":
		return true
	}
	return false
}

func hasElectronHelpers(frameworksDir, fwName string) bool {
	for _, sub := range []string{"A", "B", "Current"} {
		helpers := filepath.Join(frameworksDir, fwName, "Versions", sub, "Helpers")
		if info, err := os.Stat(helpers); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func appNameFromPath(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".app")
}

var browserBundlePrefixes = []string{
	"com.google.Chrome",
	"com.microsoft.edgemac",
	"com.brave.Browser",
	"com.opera.Opera",
	"com.vivaldi.Vivaldi",
	"org.chromium.Chromium",
	"org.mozilla.firefox",
	"com.duckduckgo.macos.browser",
	"company.thebrowser.Browser",
}

func isKnownBrowser(appPath string) bool {
	bundleID := readPlistBundleID(filepath.Join(appPath, "Contents", "Info.plist"))
	if bundleID == "" {
		return false
	}
	for _, prefix := range browserBundlePrefixes {
		if strings.HasPrefix(bundleID, prefix) {
			return true
		}
	}
	return false
}
