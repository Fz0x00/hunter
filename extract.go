package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	versionPathRe  = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	chromeStringRe = regexp.MustCompile(`Chrome/(\d{2,3}\.\d+\.\d+\.\d+)`)
)

func extractVersion(app *App, em *ElectronMap) {
	frameworksDir := filepath.Join(app.Path, "Contents", "Frameworks")
	fwDir := filepath.Join(frameworksDir, app.FrameworkName+".framework")

	if v := extractFromFrameworkPath(fwDir); v != "" {
		app.ChromiumVersion = v
		app.ExtractionMethod = MethodFrameworkPath
		return
	}

	binPath := findFrameworkBinary(fwDir)
	if binPath != "" {
		app.BinaryPath = binPath
		if v, err := extractFromBinary(binPath); err == nil && v != "" {
			app.ChromiumVersion = v
			app.ExtractionMethod = MethodBinaryStrings
			return
		}
	}

	if em != nil {
		if ev := readElectronVersionFromApp(app.Path, fwDir); ev != "" {
			if cv, ok := em.LookupChromium(ev); ok {
				app.ElectronVersion = ev
				app.ChromiumVersion = cv
				app.ExtractionMethod = MethodElectronMap
				return
			}
		}
	}

	app.ExtractionMethod = MethodNone
}

func extractFromFrameworkPath(fwDir string) string {
	versionsDir := filepath.Join(fwDir, "Versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && versionPathRe.MatchString(e.Name()) && isPlausibleChromium(e.Name()) {
			return e.Name()
		}
	}
	return ""
}

func isPlausibleChromium(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	return major >= 70 && major <= 220
}

func findFrameworkBinary(fwDir string) string {
	base := filepath.Base(fwDir)
	fwName := strings.TrimSuffix(base, ".framework")

	versionsDir := filepath.Join(fwDir, "Versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(versionsDir, e.Name(), fwName)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}
