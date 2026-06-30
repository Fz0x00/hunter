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
	chromeStringRe2 = regexp.MustCompile(`Chrome/(\d{2,3}\.\d+\.\d+\.\d+)`)
)

// extractVersion 根据框架类型定制版本提取策略
func extractVersion(app *App, em *ElectronMap) {
	switch app.Framework {
	case FrameworkCEF:
		extractCEFVersion(app)
	case FrameworkCEFFork:
		extractCEFForkVersion(app)
	case FrameworkQtWebEngine:
		extractQtVersion(app)
	case FrameworkElectron:
		extractElectronVersion(app, em)
	case FrameworkElectronFork:
		extractElectronForkVersion(app, em)
	}
}

// ---------------------------------------------------------------------------
// CEF 版本提取
//
// 官方 framework 名：Chromium Embedded Framework.framework
// 三路径降级：
//   1. Versions/X.X.X.X/ 目录名（CEF 版本号，不是 Chromium）
//   2. 二进制 strings 匹配 "Chrome/x.x.x.x"
//   3. 二进制 strings 匹配 "CEF:x.x.x.x"
// ---------------------------------------------------------------------------

func extractCEFVersion(app *App) {
	fwDir := filepath.Join(app.Path, "Contents", "Frameworks", "Chromium Embedded Framework.framework")

	// 路径 1：版本目录
	if v := extractVersionFromPath(fwDir); v != "" {
		app.ChromiumVersion = v
		app.ExtractionMethod = ExtractFrameworkPath
		return
	}

	// 路径 2：主二进制 strings
	binPath := findFrameworkBinary(fwDir)
	if binPath != "" {
		app.BinaryPath = binPath
		data, err := os.ReadFile(binPath)
		if err == nil {
			if v := findChromeVersion(data); v != "" {
				app.ChromiumVersion = v
				app.ExtractionMethod = ExtractBinaryStrings
				return
			}
			// 路径 3：CEF 版本号
			if v := findCEFVersion(data); v != "" {
				app.CEFVersion = v
				app.ExtractionMethod = ExtractCEFVersion
				return
			}
		}
	}

	app.ExtractionMethod = ExtractNone
}

// ---------------------------------------------------------------------------
// CEF Fork 版本提取（封装版 CEF，如钉钉）
//
// 没有标准 framework，需要在所有 dylib 和主程序里搜索
// 优先级：dylib > 主程序（主程序通常只有 UA 字符串，不是真实渲染引擎版本）
// 多特征验证：区分 UA 字符串和真实渲染引擎版本
// ---------------------------------------------------------------------------

func extractCEFForkVersion(app *App) {
	// 搜索所有可能的二进制：主程序 + Frameworks/*.dylib
	candidates := []string{}

	// 优先：Frameworks 下的 dylib（真实渲染引擎版本在这里）
	fwDir := filepath.Join(app.Path, "Contents", "Frameworks")
	if entries, err := os.ReadDir(fwDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".dylib") {
				candidates = append(candidates, filepath.Join(fwDir, e.Name()))
			}
		}
	}

	// 其次：主程序（通常只有 UA 字符串）
	mainBin := findAppMainBinary(app.Path)
	if mainBin != "" {
		candidates = append(candidates, mainBin)
	}

	// 优先取 dylib 中的版本（真实渲染引擎）
	for _, binPath := range candidates {
		data, err := os.ReadFile(binPath)
		if err != nil {
			continue
		}
		if v := findChromeVersion(data); v != "" {
			// 检查是否是 UA 字符串
			if findChromeVersionInUA(data) {
				// 如果是 UA 字符串，跳过（除非是 dylib 且没有其他选择）
				if strings.HasSuffix(binPath, ".dylib") {
					// 继续检查其他 dylib
					continue
				}
				continue
			}
			app.ChromiumVersion = v
			app.BinaryPath = binPath
			app.ExtractionMethod = ExtractBinaryStrings
			// 如果是 dylib，直接返回（优先）
			if strings.HasSuffix(binPath, ".dylib") {
				return
			}
		}
	}

	// 如果所有版本都是 UA 字符串，尝试提取第一个作为参考
	for _, binPath := range candidates {
		data, err := os.ReadFile(binPath)
		if err != nil {
			continue
		}
		if v := findChromeVersion(data); v != "" {
			app.ChromiumVersion = v
			app.BinaryPath = binPath
			app.ExtractionMethod = ExtractBinaryStrings
			// 标记为 UA 字符串
			app.FrameworkName += " (UA)"
			return
		}
	}

	app.ExtractionMethod = ExtractNone
}

// ---------------------------------------------------------------------------
// Qt WebEngine 版本提取
//
// 官方 framework 名：QtWebEngineCore.framework
// 三路径降级：
//   1. Versions/X.X.X.X/ 目录名（Qt 版本号，不是 Chromium）
//   2. 二进制 strings 匹配 "Chrome/x.x.x.x"
//   3. 从 Info.plist 的 CFBundleShortVersionString 获取 Qt 版本（辅助信息）
// ---------------------------------------------------------------------------

func extractQtVersion(app *App) {
	fwDir := filepath.Join(app.Path, "Contents", "Frameworks", "QtWebEngineCore.framework")

	// 路径 1：版本目录（Qt 版本号）
	if v := extractVersionFromPath(fwDir); v != "" {
		// Qt 版本号格式是 5.x.x 或 6.x.x，不是 Chromium 版本
		// 需要降级到 strings
	}

	// 路径 2：主二进制 strings
	binPath := findFrameworkBinary(fwDir)
	if binPath != "" {
		app.BinaryPath = binPath
		if v, err := extractFromBinary(binPath); err == nil && v != "" {
			app.ChromiumVersion = v
			app.ExtractionMethod = ExtractBinaryStrings
			return
		}
	}

	// 路径 3：Qt 版本号（从 Info.plist，作为辅助信息）
	if v := readPlistField(filepath.Join(fwDir, "Versions", "A", "Resources", "Info.plist"), "CFBundleShortVersionString"); v != "" {
		app.ElectronVersion = v // 复用这个字段存 Qt 版本
	}

	app.ExtractionMethod = ExtractNone
}

// ---------------------------------------------------------------------------
// 标准 Electron 版本提取
//
// 三路径降级：
//   1. Versions/X.X.X.X/ 目录名（Chromium 版本，飞书等直接暴露）
//   2. 二进制 strings 匹配 "Chrome/x.x.x.x"（大多数 Electron 应用）
//   3. Info.plist Electron 版本 → electron-map 映射表
// ---------------------------------------------------------------------------

func extractElectronVersion(app *App, em *ElectronMap) {
	fwDir := filepath.Join(app.Path, "Contents", "Frameworks", "Electron Framework.framework")

	// 路径 1：版本目录
	if v := extractVersionFromPath(fwDir); v != "" {
		app.ChromiumVersion = v
		app.ExtractionMethod = ExtractFrameworkPath
		return
	}

	// 路径 2：主二进制 strings
	binPath := findFrameworkBinary(fwDir)
	if binPath != "" {
		app.BinaryPath = binPath
		if v, err := extractFromBinary(binPath); err == nil && v != "" {
			app.ChromiumVersion = v
			app.ExtractionMethod = ExtractBinaryStrings
			return
		}
	}

	// 路径 3：Electron 映射表
	if em != nil {
		if ev := readElectronVersionFromApp(app.Path, fwDir); ev != "" {
			if cv, ok := em.LookupChromium(ev); ok {
				app.ElectronVersion = ev
				app.ChromiumVersion = cv
				app.ExtractionMethod = ExtractElectronMap
				return
			}
		}
	}

	app.ExtractionMethod = ExtractNone
}

// ---------------------------------------------------------------------------
// Electron Fork 版本提取
//
// 自定义 framework 名（如 Lark Framework.framework），结构与标准 Electron 相同
// 降级链同标准 Electron，但 framework 目录不同
// ---------------------------------------------------------------------------

func extractElectronForkVersion(app *App, em *ElectronMap) {
	fwDir := filepath.Join(app.Path, "Contents", "Frameworks", app.FrameworkName+".framework")

	// 路径 1：版本目录
	if v := extractVersionFromPath(fwDir); v != "" {
		app.ChromiumVersion = v
		app.ExtractionMethod = ExtractFrameworkPath
		return
	}

	// 路径 2：主二进制 strings
	binPath := findFrameworkBinary(fwDir)
	if binPath != "" {
		app.BinaryPath = binPath
		if v, err := extractFromBinary(binPath); err == nil && v != "" {
			app.ChromiumVersion = v
			app.ExtractionMethod = ExtractBinaryStrings
			return
		}
	}

	// 路径 3：Electron 映射表
	if em != nil {
		if ev := readElectronVersionFromApp(app.Path, fwDir); ev != "" {
			if cv, ok := em.LookupChromium(ev); ok {
				app.ElectronVersion = ev
				app.ChromiumVersion = cv
				app.ExtractionMethod = ExtractElectronMap
				return
			}
		}
	}

	app.ExtractionMethod = ExtractNone
}

// ---------------------------------------------------------------------------
// 通用辅助函数
// ---------------------------------------------------------------------------

// extractVersionFromPath 从 framework 的 Versions/ 目录提取版本号
func extractVersionFromPath(fwDir string) string {
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

// isPlausibleChromium 判断版本号是否是合理的 Chromium 版本（≥70, ≤220）
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
