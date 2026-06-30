package main

import "time"

// Framework 类型枚举（按官方部署规范定义）
type Framework string

const (
	// 官方 Electron：Electron Framework.framework（固定名）
	FrameworkElectron Framework = "electron"
	// Electron Fork：自定义 framework 名（Lark Framework.framework 等）
	FrameworkElectronFork Framework = "electron_fork"
	// 官方 CEF：Chromium Embedded Framework.framework（强制名）
	FrameworkCEF Framework = "cef"
	// CEF 封装：应用把 CEF 链接进自命名库（libdt_web_view.dylib 等）
	FrameworkCEFFork Framework = "cef_fork"
	// 官方 Qt WebEngine：QtWebEngineCore.framework
	FrameworkQtWebEngine Framework = "qt_webengine"
)

// 检测方法（决定性特征的来源）
type DetectionMethod string

const (
	// 目录结构匹配（官方 framework 名或标准布局）
	DetMethodDirectory DetectionMethod = "directory"
	// 二进制 strings 匹配（兜底检测）
	DetMethodBinaryStrings DetectionMethod = "binary_strings"
	// 组合判定（目录 + 二进制交叉验证）
	DetMethodCombined DetectionMethod = "combined"
)

// 版本提取方法（优先级降级链）
type ExtractionMethod string

const (
	ExtractFrameworkPath ExtractionMethod = "framework_path"  // Versions/X.X.X.X/ 目录名
	ExtractBinaryStrings ExtractionMethod = "binary_strings"  // 二进制 Chrome/x.x.x.x
	ExtractElectronMap   ExtractionMethod = "electron_mapping" // Info.plist Electron版本 → 映射表
	ExtractCEFVersion    ExtractionMethod = "cef_version"     // Chromium Embedded Framework 版本
	ExtractNone          ExtractionMethod = "unknown"
)

// App 表示一个被检测到的 Chromium 嵌入式应用
type App struct {
	Name             string           `json:"app_name"`
	Path             string           `json:"app_path"`
	Framework        Framework        `json:"framework"`
	FrameworkName    string           `json:"framework_name,omitempty"`
	Detection        DetectionMethod  `json:"detection"`
	ChromiumVersion  string           `json:"chromium_version,omitempty"`
	ElectronVersion  string           `json:"electron_version,omitempty"`
	CEFVersion       string           `json:"cef_version,omitempty"`
	ExtractionMethod ExtractionMethod `json:"extraction_method,omitempty"`
	BinaryPath       string           `json:"binary_path,omitempty"`
}

// ScanResult 表示一次扫描的完整结果
type ScanResult struct {
	Platform  string    `json:"platform"`
	ScanTime  string    `json:"scan_time"`
	Scope     string    `json:"scope"`
	Total     int       `json:"total_apps"`
	WithCVER  int       `json:"with_chromium_version"`
	Apps      []App     `json:"apps"`
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
