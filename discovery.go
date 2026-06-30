package main

import (
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// 公共路径
// ---------------------------------------------------------------------------

func defaultScanPaths() []string {
	var paths []string
	paths = append(paths, "/Applications")
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, "Applications"))
	}
	return paths
}

func appNameFromPath(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".app")
}

// ---------------------------------------------------------------------------
// 主入口：扫描根目录，发现所有 Chromium 嵌入式应用
// ---------------------------------------------------------------------------

func discoverApps(roots []string) []App {
	var apps []App
	seen := map[string]bool{}

	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			appPath := filepath.Join(root, entry.Name())
			if seen[appPath] {
				continue
			}
			// 先检测 .app 本体
			if app, ok := inspectApp(appPath); ok {
				seen[appPath] = true
				apps = append(apps, app)
			}
			// 递归扫描嵌套 .app（微信/QQ 把 Chromium 引擎藏在 MacOS/ 或 Resources/ 下）
			for _, nested := range findNestedApps(appPath) {
				if seen[nested] {
					continue
				}
				if app, ok := inspectApp(nested); ok {
					seen[nested] = true
					// 用父应用名做前缀，区分嵌套引擎
					base := appNameFromPath(appPath)
					if app.Name == appNameFromPath(nested) {
						app.Name = base + " / " + app.Name
					} else {
						app.Name = base + " / " + app.Name
					}
					apps = append(apps, app)
				}
			}
		}
	}
	return apps
}

// findNestedApps 在 .app 包内搜索嵌套的 .app
// 微信 WeChatAppEx 在 Contents/MacOS/
// QQ QQEXMiniProgram 在 Contents/Resources/
// 豆包 Doubao Browser 在 Contents/Helpers/
func findNestedApps(appPath string) []string {
	var nested []string
	subs := []string{
		filepath.Join(appPath, "Contents", "MacOS"),
		filepath.Join(appPath, "Contents", "Resources"),
		filepath.Join(appPath, "Contents", "Helpers"),
	}
	for _, dir := range subs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
				nested = append(nested, filepath.Join(dir, e.Name()))
			}
		}
	}
	return nested
}

// ---------------------------------------------------------------------------
// inspectApp：按优先级级联检测框架类型
//
// 决策树（来自 framework-detection.md）：
//   1. 排除原生浏览器
//   2. Qt WebEngine（特征最独特：Qt 全家桶）
//   3. CEF（官方强制 framework 名 + libcef + 二进制标记兜底）
//   4. CEF Fork（自研 CEF 封装，如钉钉 xriver）
//   5. 标准 Electron（官方固定 framework 名）
//   6. Electron Fork（自定义 framework + Helpers 目录 + 二进制确认）
// ---------------------------------------------------------------------------

func inspectApp(appPath string) (App, bool) {
	// Step 1: 排除浏览器本身
	if isKnownBrowser(appPath) {
		return App{}, false
	}

	frameworksDir := filepath.Join(appPath, "Contents", "Frameworks")
	fwEntries, err := os.ReadDir(frameworksDir)
	if err != nil {
		return App{}, false
	}

	name := appNameFromPath(appPath)

	// Step 2: Qt WebEngine（优先级最高，特征最独特）
	if fw := detectQtWebEngine(frameworksDir, fwEntries); fw != "" {
		return App{
			Name: name, Path: appPath,
			Framework: FrameworkQtWebEngine, FrameworkName: fw,
			Detection: DetMethodDirectory,
		}, true
	}

	// Step 3: CEF（三路径检测）
	if fw, method := detectCEF(appPath, frameworksDir, fwEntries); fw != "" {
		return App{
			Name: name, Path: appPath,
			Framework: FrameworkCEF, FrameworkName: fw,
			Detection: method,
		}, true
	}

	// Step 4: CEF Fork（自研 CEF 封装，如钉钉 xriver）
	if fw, method := detectCEFFork(appPath, frameworksDir, fwEntries); fw != "" {
		return App{
			Name: name, Path: appPath,
			Framework: FrameworkCEFFork, FrameworkName: fw,
			Detection: method,
		}, true
	}

	// Step 5: 标准 Electron
	if fw := detectStandardElectron(frameworksDir, fwEntries); fw != "" {
		return App{
			Name: name, Path: appPath,
			Framework: FrameworkElectron, FrameworkName: fw,
			Detection: DetMethodDirectory,
		}, true
	}

	// Step 6: Electron Fork（自定义 framework + 二进制确认）
	if fw, method := detectElectronFork(appPath, frameworksDir, fwEntries); fw != "" {
		return App{
			Name: name, Path: appPath,
			Framework: FrameworkElectronFork, FrameworkName: fw,
			Detection: method,
		}, true
	}

	return App{}, false
}

// ---------------------------------------------------------------------------
// Step 2: Qt WebEngine 检测
//
// 官方决定性特征：Contents/Frameworks/QtWebEngineCore.framework/ 存在
// 辅助特征：同目录下有 QtCore.framework（Qt 全家桶）
// ---------------------------------------------------------------------------

func detectQtWebEngine(frameworksDir string, entries []os.DirEntry) string {
	// 决定性特征：QtWebEngineCore.framework 存在
	qtFw := filepath.Join(frameworksDir, "QtWebEngineCore.framework")
	if _, err := os.Stat(qtFw); err == nil {
		return "QtWebEngineCore"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Step 3: CEF 检测（三路径，按优先级）
//
// 路径 1（官方标准）：Contents/Frameworks/Chromium Embedded Framework.framework/
//   → CEF 官方强制框架名（macOS 沙箱实现要求）
//
// 路径 2（标准库形式）：Frameworks/libcef.dylib / libcef.dll / libcef.so
//   → Windows/Linux 标准形式，macOS 少见但可能
//
// 路径 3（二进制标记兜底）：主程序或 dylib 里 CefBrowser 标记 ≥10 处
//   → 应用把 CEF 静态链接或封装进自命名库（如钉钉 libdt_web_view.dylib）
// ---------------------------------------------------------------------------

func detectCEF(appPath string, frameworksDir string, entries []os.DirEntry) (string, DetectionMethod) {
	// 路径 1：官方强制 framework 名
	const cefFwName = "Chromium Embedded Framework.framework"
	if _, err := os.Stat(filepath.Join(frameworksDir, cefFwName)); err == nil {
		return cefFwName, DetMethodDirectory
	}

	// 路径 2：libcef 共享库
	for _, name := range []string{"libcef.dylib", "libcef.dll", "libcef.so"} {
		if _, err := os.Stat(filepath.Join(frameworksDir, name)); err == nil {
			return name, DetMethodDirectory
		}
	}

	// 路径 3：二进制标记兜底（主程序 + Framework 二进制 + dylib）
	// 阿里系应用（Qianwen/Taobao）的 CEF 标记藏在 Framework 二进制里，主程序里没有
	allBinaries := []string{}
	if mainBin := findAppMainBinary(appPath); mainBin != "" {
		allBinaries = append(allBinaries, mainBin)
	}
	for _, e := range entries {
		if !e.IsDir() {
			bin := filepath.Join(frameworksDir, e.Name())
			if info, err := os.Stat(bin); err == nil && info.Mode()&0111 != 0 {
				allBinaries = append(allBinaries, bin)
			}
		}
	}
	for _, bin := range allBinaries {
		if countCEFBinaryMarkers(bin) >= cefThreshold {
			name := "embedded binary"
			if bin != findAppMainBinary(appPath) {
				name = "embedded: " + filepath.Base(bin)
			}
			return "CEF (" + name + ")", DetMethodBinaryStrings
		}
	}

	return "", ""
}

// ---------------------------------------------------------------------------
// WebKit/WKWebView 检测（用于排除非 Chromium 应用）
//
// 如果检测到 WKWebView/WebKit 证据，但没有 Blink/V8 证据，
// 则认为应用使用的是 WebKit 而非 Chromium 渲染引擎
// ---------------------------------------------------------------------------

func hasWebKitEvidence(appPath string, frameworksDir string, entries []os.DirEntry) bool {
	// 检查所有二进制文件中的 WebKit 标记
	allBinaries := []string{}
	if mainBin := findAppMainBinary(appPath); mainBin != "" {
		allBinaries = append(allBinaries, mainBin)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".dylib") {
			allBinaries = append(allBinaries, filepath.Join(frameworksDir, e.Name()))
		}
	}

	for _, bin := range allBinaries {
		if countWebKitMarkers(bin) >= 2 {
			return true
		}
	}
	return false
}

// hasBlinkV8Evidence 检查是否有 Blink/V8 证据（确认 Chromium 渲染引擎）
func hasBlinkV8Evidence(appPath string, frameworksDir string, entries []os.DirEntry) bool {
	allBinaries := []string{}
	if mainBin := findAppMainBinary(appPath); mainBin != "" {
		allBinaries = append(allBinaries, mainBin)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".dylib") {
			allBinaries = append(allBinaries, filepath.Join(frameworksDir, e.Name()))
		}
	}

	for _, bin := range allBinaries {
		if countBlinkV8Markers(bin) >= 2 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Step 4: CEF Fork 检测（自研 CEF 封装，多特征交叉验证）
//
// 特征（必须同时满足）：
//   - 自定义 dylib（libdt_web_view.dylib, libdtriver.dylib 等）
//   - 二进制标记：dtcef、CGraySwitch、xriver 等
//   - 没有标准 CEF framework（Chromium Embedded Framework.framework）
//   - 但排除：有 WKWebView/WebKit 证据但没有 Blink/V8 证据的应用
//
// 示例：钉钉（DingTalk）使用 WKWebView，dtcef 只是命名空间
// ---------------------------------------------------------------------------

func detectCEFFork(appPath string, frameworksDir string, entries []os.DirEntry) (string, DetectionMethod) {
	// 先检查是否有 CEF fork 标记
	hasCEFForkMarkers := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dylib") {
			continue
		}
		dylibPath := filepath.Join(frameworksDir, e.Name())
		if countCEFForkBinaryMarkers(dylibPath) >= cefForkThreshold {
			hasCEFForkMarkers = true
			break
		}
	}
	if !hasCEFForkMarkers {
		if mainBin := findAppMainBinary(appPath); mainBin != "" {
			if countCEFForkBinaryMarkers(mainBin) >= cefForkThreshold {
				hasCEFForkMarkers = true
			}
		}
	}

	if !hasCEFForkMarkers {
		return "", ""
	}

	// 多特征交叉验证：检查是否有真实 Chromium 渲染引擎
	hasWebKit := hasWebKitEvidence(appPath, frameworksDir, entries)
	hasBlinkV8 := hasBlinkV8Evidence(appPath, frameworksDir, entries)

	// 如果有 WebKit 证据但没有 Blink/V8 证据，说明用的是 WKWebView，不是 Chromium
	if hasWebKit && !hasBlinkV8 {
		return "", ""
	}

	// 返回检测结果
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dylib") {
			continue
		}
		dylibPath := filepath.Join(frameworksDir, e.Name())
		if countCEFForkBinaryMarkers(dylibPath) >= cefForkThreshold {
			return "CEF Fork (" + e.Name() + ")", DetMethodCombined
		}
	}

	if mainBin := findAppMainBinary(appPath); mainBin != "" {
		if countCEFForkBinaryMarkers(mainBin) >= cefForkThreshold {
			return "CEF Fork (main binary)", DetMethodCombined
		}
	}

	return "", ""
}

// ---------------------------------------------------------------------------
// Step 5: 标准 Electron 检测（renumbered from Step 4）
//
// 官方决定性特征：Contents/Frameworks/Electron Framework.framework/ 存在
//   （electron-packager/electron-builder 的固定产物）
// ---------------------------------------------------------------------------

func detectStandardElectron(frameworksDir string, entries []os.DirEntry) string {
	for _, e := range entries {
		if e.IsDir() && e.Name() == "Electron Framework.framework" {
			return "Electron Framework"
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Step 6: Electron Fork 检测
//
// 特征：非标准 framework 名 + Helpers 目录结构 + 二进制 Electron 标记
// 示例：Lark Framework.framework / Qianwen Framework.framework
//
// 注意：必须排除 Qt 框架（Qt*.framework）和已知非框架（Squirrel/Sparkle 等）
// ---------------------------------------------------------------------------

func detectElectronFork(appPath string, frameworksDir string, entries []os.DirEntry) (string, DetectionMethod) {
	// 收集所有可执行文件（主程序 + Framework 二进制）
	// 某些 Electron Fork（飞书/千问）的 Electron 标记只在 Framework 二进制里
	type candidate struct {
		fwName string
		bin    string
	}
	var candidates []candidate
	if mainBin := findAppMainBinary(appPath); mainBin != "" {
		candidates = append(candidates, candidate{"", mainBin})
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fwName := e.Name()
		if !strings.HasSuffix(fwName, ".framework") {
			continue
		}
		if isKnownNonFramework(fwName) || isQtFramework(fwName) {
			continue
		}
		if !hasElectronHelpers(frameworksDir, fwName) {
			continue
		}
		if bin := findFrameworkBinary(filepath.Join(frameworksDir, fwName)); bin != "" {
			candidates = append(candidates, candidate{fwName, bin})
		}
	}
	for _, c := range candidates {
		count := countElectronBinaryMarkers(c.bin)
		if count >= electronThreshold {
			if c.fwName != "" {
				return strings.TrimSuffix(c.fwName, ".framework"), DetMethodCombined
			}
			return "electron_fork", DetMethodCombined
		}
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// 已知框架判断辅助函数
// ---------------------------------------------------------------------------

// isQtFramework 判断是否为 Qt 相关框架
func isQtFramework(name string) bool {
	return strings.HasPrefix(name, "Qt") && strings.HasSuffix(name, ".framework")
}

// isKnownNonFramework 判断是否为已知的辅助/依赖框架（非 Chromium）
func isKnownNonFramework(name string) bool {
	switch name {
	case "Electron Framework.framework",
		"Chromium Embedded Framework.framework",
		"Squirrel.framework",
		"ReactiveCocoa.framework",
		"Mantle.framework",
		"Sparkle.framework",
		"Growl.framework",
		"Google Chrome Framework.framework",
		"Microsoft Edge Framework.framework":
		return true
	}
	return false
}

// hasElectronHelpers 检查是否有 Electron 风格的 Helper 应用
//
// 两种布局：
//   1. 标准/Fork Electron：framework/Versions/*/Helpers/ 目录
//   2. QQNT 式：Helpers 直接放在 Contents/Frameworks/ 下（*Helper*.app）
func hasElectronHelpers(frameworksDir, fwName string) bool {
	// 布局 1：framework 内部 Helpers 目录
	versionsDir := filepath.Join(frameworksDir, fwName, "Versions")
	if entries, err := os.ReadDir(versionsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			helpers := filepath.Join(versionsDir, e.Name(), "Helpers")
			if info, err := os.Stat(helpers); err == nil && info.IsDir() {
				return true
			}
		}
	}
	// 布局 2：Frameworks 目录下直接有 *Helper*.app（QQNT 结构）
	// QQ 的 framework 叫 QQNT.framework，但 Helper 叫 QQ Helper.app，名字不一致
	// 所以用 Electron 专有的 Helper 角色来确认：Renderer/GPU/Plugin
	if entries, err := os.ReadDir(frameworksDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			if strings.Contains(e.Name(), "Helper (Renderer)") ||
				strings.Contains(e.Name(), "Helper (GPU)") ||
				strings.Contains(e.Name(), "Helper (Plugin)") {
				return true
			}
		}
	}
	return false
}

// findAppMainBinary 找到 .app 包内的主可执行文件
func findAppMainBinary(appPath string) string {
	bundleID := readPlistBundleID(filepath.Join(appPath, "Contents", "Info.plist"))
	if bundleID == "" {
		// fallback: 用 Info.plist 的 CFBundleName 或 app 目录名
		name := appNameFromPath(appPath)
		candidate := filepath.Join(appPath, "Contents", "MacOS", name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		return ""
	}
	// 用 bundleID 找可执行文件
	parts := strings.Split(bundleID, ".")
	if len(parts) == 0 {
		return ""
	}
	candidate := filepath.Join(appPath, "Contents", "MacOS", parts[len(parts)-1])
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	// fallback: 用 app 名
	name := appNameFromPath(appPath)
	candidate = filepath.Join(appPath, "Contents", "MacOS", name)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	return ""
}

// findFrameworkBinary 找到 framework 内的主二进制
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

// ---------------------------------------------------------------------------
// 浏览器排除
// ---------------------------------------------------------------------------

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
