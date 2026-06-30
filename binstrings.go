package main

import (
	"bytes"
	"io"
	"os"
	"regexp"
)

// ---------------------------------------------------------------------------
// 版本提取正则
// ---------------------------------------------------------------------------

var (
	chromeVersionRe = regexp.MustCompile(`Chrome/(\d{2,3}\.\d+\.\d+\.\d+)`)
	cefVersionRe    = regexp.MustCompile(`CEF[:\s]+(\d+\.\d+\.\d+\.\d+)`)
)

func extractFromBinary(binPath string) (string, error) {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return "", err
	}
	return findChromeVersion(data), nil
}

func findChromeVersion(data []byte) string {
	matches := chromeVersionRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, m := range matches {
		counts[string(m[1])]++
	}
	var best string
	var bestCount int
	for v, c := range counts {
		if c > bestCount {
			best = v
			bestCount = c
		}
	}
	return best
}

func findCEFVersion(data []byte) string {
	m := cefVersionRe.FindSubmatch(data)
	if len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

// ---------------------------------------------------------------------------
// 二进制标记检测
//
// 流式读取二进制文件（1MB chunk），用 bytes.Contains 检测标记。
// 用 bitset 跟踪已发现的标记，达到阈值后立即返回。
// ---------------------------------------------------------------------------

const (
	cefThreshold       = 10
	electronThreshold  = 5   // Electron 标记确认（≥5 个不同标记命中 → 确认 Fork）
	cefForkThreshold   = 3   // CEF Fork 标记确认（≥3 个不同标记命中 → 确认 Fork）
	chunkSize          = 1024 * 1024 // 1MB
)

var cefMarkers = [][]byte{
	[]byte("cef_"), []byte("CefBrowser"), []byte("CefContext"), []byte("CefSettings"),
	[]byte("CefRequestContext"), []byte("CefResourceRequestHandler"), []byte("CefLifeSpanHandler"),
	[]byte("CefLoadHandler"), []byte("CefDisplayHandler"), []byte("CefRequestHandler"),
	[]byte("CefClient"), []byte("CefApp"), []byte("CefV8"), []byte("CefProcessMessage"),
	[]byte("CefString"), []byte("CefBase"), []byte("CefSettingsTraits"),
	[]byte("cef_execute_process"), []byte("cef_initialize"), []byte("cef_shutdown"),
	[]byte("cef_do_message_loop_work"), []byte("cef_register_schema_handler"),
	[]byte("cef_string_multimap_alloc"), []byte("libcef_"),
}

var electronMarkers = [][]byte{
	[]byte("update_from_electron"), []byte("com.electron."), []byte("BrowserWindow"),
	[]byte("webContents"), []byte("Chromium Embedded Framework"),
	[]byte("register_atom_browser"), []byte("atom_browser"), []byte("ElectronMain"),
	[]byte("chrome_crashpad_handler"), []byte("libchromiumcontent"),
	[]byte("content::ContentMainRunner"), []byte("content::WebContents"),
	[]byte("content::RenderWidgetHost"), []byte("content::FrameType"),
	[]byte("content::ProtocolHandler"), []byte("Startup.LoadTime.ApplicationStartToChromeMain"),
}

var cefForkMarkers = [][]byte{
	// 钉钉 xriver/cef fork
	[]byte("dtcef"), []byte("CGraySwitch"), []byte("xriver"),
	[]byte("libdtriver"), []byte("libdt_web_view"),
	// 通用 CEF fork 特征
	[]byte("CEF_VERSION"), []byte("cef_execute_process"),
	[]byte("CefBrowserHost"), []byte("CefFrame"),
	// 阿里系应用
	[]byte("emas"), []byte("xbase_cr"),
}

// WebKit/WKWebView 标记（用于排除非 Chromium 应用）
var webkitMarkers = [][]byte{
	[]byte("WKWebView"), []byte("WKWeb"), []byte("WebKit"),
	[]byte("JSCContext"), []byte("JSCValue"),
	[]byte("JavaScriptCore"), []byte("WKNavigation"),
	[]byte("WKURLSchemeHandler"),
}

// Blink/V8 标记（用于确认 Chromium 渲染引擎）
var blinkV8Markers = [][]byte{
	[]byte("blink::"), []byte("v8::Isolate"), []byte("v8::Context"),
	[]byte("content::RenderFrame"), []byte("content::WebContents"),
	[]byte("Blink/"), []byte("third_party/blink"),
}

func countCEFBinaryMarkers(path string) int {
	return countMarkers(path, cefMarkers, cefThreshold)
}

func countElectronBinaryMarkers(path string) int {
	return countMarkers(path, electronMarkers, electronThreshold)
}

func countCEFForkBinaryMarkers(path string) int {
	return countMarkers(path, cefForkMarkers, cefForkThreshold)
}

func countWebKitMarkers(path string) int {
	return countMarkers(path, webkitMarkers, 2) // ≥2 个 WebKit 标记
}

func countBlinkV8Markers(path string) int {
	return countMarkers(path, blinkV8Markers, 2) // ≥2 个 Blink/V8 标记
}

// findChromeVersionInUA 检测 Chrome 版本是否来自 UA 字符串
// 返回 true 如果是 UA 字符串（仅用于兼容性，非真实渲染引擎）
func findChromeVersionInUA(data []byte) bool {
	// UA 字符串特征：包含 Safari/537.36 或 AppleWebKit/537.36
	uaPatterns := [][]byte{
		[]byte("Safari/537.36"),
		[]byte("AppleWebKit/537.36"),
		[]byte("Mozilla/5.0"),
	}
	
	// 查找所有 Chrome 版本
	matches := chromeVersionRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return false
	}
	
	// 检查每个 Chrome 版本的上下文
	for _, loc := range matches {
		if len(loc) < 4 {
			continue
		}
		// 获取 Chrome 版本前后 200 字节的上下文
		start := loc[0]
		if start > 200 {
			start -= 200
		}
		end := loc[1]
		if end+200 < len(data) {
			end += 200
		} else {
			end = len(data)
		}
		context := data[start:end]
		
		// 检查是否包含 UA 字符串特征
		for _, pattern := range uaPatterns {
			if bytes.Contains(context, pattern) {
				return true
			}
		}
	}
	return false
}

func countMarkers(path string, markers [][]byte, threshold int) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	found := make([]bool, len(markers))
	count := 0
	buf := make([]byte, chunkSize)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for i, m := range markers {
				if !found[i] && bytes.Contains(chunk, m) {
					found[i] = true
					count++
					if count >= threshold {
						return count
					}
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			break
		}
	}
	return count
}
