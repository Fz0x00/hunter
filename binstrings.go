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
	cefThreshold      = 10
	electronThreshold = 5   // Electron 标记确认（≥5 个不同标记命中 → 确认 Fork）
	chunkSize         = 1024 * 1024 // 1MB
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

func countCEFBinaryMarkers(path string) int {
	return countMarkers(path, cefMarkers, cefThreshold)
}

func countElectronBinaryMarkers(path string) int {
	return countMarkers(path, electronMarkers, electronThreshold)
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
