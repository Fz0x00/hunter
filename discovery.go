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

	name := appNameFromPath(appPath)

	if fw := detectQtWebEngine(frameworksDir); fw != "" {
		return App{Name: name, Path: appPath, Framework: FrameworkQtWebEngine, FrameworkName: fw}, true
	}

	if fw := detectCEF(frameworksDir, entries); fw != "" {
		return App{Name: name, Path: appPath, Framework: FrameworkCEF, FrameworkName: fw}, true
	}

	if isStandardElectron(entries) {
		return App{Name: name, Path: appPath, Framework: FrameworkElectron, FrameworkName: "Electron Framework"}, true
	}

	if fw := detectElectronFork(frameworksDir, entries); fw != "" {
		return App{Name: name, Path: appPath, Framework: FrameworkElectronFork, FrameworkName: fw}, true
	}

	return App{}, false
}

func isStandardElectron(entries []os.DirEntry) bool {
	for _, e := range entries {
		if e.IsDir() && e.Name() == "Electron Framework.framework" {
			return true
		}
	}
	return false
}

func detectQtWebEngine(frameworksDir string) string {
	qtFw := filepath.Join(frameworksDir, "QtWebEngineCore.framework")
	if info, err := os.Stat(qtFw); err == nil && info.IsDir() {
		return "QtWebEngineCore"
	}
	return ""
}

func detectCEF(frameworksDir string, entries []os.DirEntry) string {
	for _, name := range []string{"libcef.dylib", "libcef.dll", "libcef.so"} {
		if _, err := os.Stat(filepath.Join(frameworksDir, name)); err == nil {
			return "CEF"
		}
	}
	for _, e := range entries {
		n := e.Name()
		if strings.Contains(strings.ToLower(n), "cef") && (strings.HasSuffix(n, ".framework") || strings.HasSuffix(n, ".dylib")) {
			if !isKnownNonFramework(n) {
				return strings.TrimSuffix(n, ".framework")
			}
		}
	}
	return ""
}

func detectElectronFork(frameworksDir string, entries []os.DirEntry) string {
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".framework") {
			continue
		}
		if isKnownNonFramework(name) || isQtFramework(name) {
			continue
		}
		if hasElectronHelpers(frameworksDir, name) {
			return strings.TrimSuffix(name, ".framework")
		}
	}
	return ""
}

func isQtFramework(name string) bool {
	return strings.HasPrefix(name, "Qt") && strings.HasSuffix(name, ".framework")
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
