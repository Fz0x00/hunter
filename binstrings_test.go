package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// 写一个假二进制到临时文件，然后用 countMarkers 测试
func writeFakeBinary(t *testing.T, name string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestFindChromeVersion(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty", "", ""},
		{"single", "Chrome/118.0.5993.54", "118.0.5993.54"},
		{"multiple same", "Chrome/118.0.5993.54 Chrome/118.0.5993.54", "118.0.5993.54"},
		{"multiple different counts", "Chrome/118.0.5993.54 Chrome/140.0.0.0 Chrome/140.0.0.0", "140.0.0.0"},
		{"ua string", "Mozilla/5.0 Chrome/140.0.0.0 Safari/537.36", "140.0.0.0"},
		{"no match", "Chrome 118", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findChromeVersion([]byte(tc.data))
			if got != tc.want {
				t.Errorf("findChromeVersion(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestFindChromeVersionInUA(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"real chrome version", "Chrome/118.0.5993.54 some random context", false},
		{"ua with safari", "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36", true},
		{"ua short", "Chrome/87.0.4280.141 Safari/537.36", true},
		{"no chrome", "nothing here", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findChromeVersionInUA([]byte(tc.data))
			if got != tc.want {
				t.Errorf("findChromeVersionInUA(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestCountMarkers(t *testing.T) {
	// CEF markers: 给一个含 12 个不同 CEF 标记的假二进制
	cefBin := writeFakeBinary(t, "fake_cef",
		[]byte("cef_ CefBrowser CefContext CefSettings CefRequestContext CefResourceRequestHandler CefLifeSpanHandler CefLoadHandler CefDisplayHandler CefRequestHandler CefClient CefApp CefV8"))
	if got := countMarkers(cefBin, cefMarkers, cefThreshold); got < cefThreshold {
		t.Errorf("expected >= %d CEF markers, got %d", cefThreshold, got)
	}

	// 空二进制
	emptyBin := writeFakeBinary(t, "empty", []byte("nothing"))
	if got := countMarkers(emptyBin, cefMarkers, cefThreshold); got != 0 {
		t.Errorf("expected 0 markers for empty binary, got %d", got)
	}
}

func TestCountWebKitMarkers(t *testing.T) {
	// 模拟 DingTalk：有 WebKit 标记
	webkitBin := writeFakeBinary(t, "webkit",
		[]byte("WKWebView JSCContext JavaScriptCore WKNavigation"))
	if got := countMarkers(webkitBin, webkitMarkers, 2); got < 2 {
		t.Errorf("expected >= 2 WebKit markers, got %d", got)
	}

	// 无 WebKit 标记
	noWebkit := writeFakeBinary(t, "no_webkit", []byte("cef_ CefBrowser"))
	if got := countMarkers(noWebkit, webkitMarkers, 2); got != 0 {
		t.Errorf("expected 0 WebKit markers, got %d", got)
	}
}

func TestCountBlinkV8Markers(t *testing.T) {
	// 真实 Chromium 应用：有 Blink/V8 标记
	blinkBin := writeFakeBinary(t, "blink",
		[]byte("blink::RenderView v8::Isolate content::WebContents v8::Context"))
	if got := countMarkers(blinkBin, blinkV8Markers, 2); got < 2 {
		t.Errorf("expected >= 2 Blink/V8 markers, got %d", got)
	}

	// WebKit 应用：没有 Blink/V8
	noBlink := writeFakeBinary(t, "no_blink", []byte("WKWebView JavaScriptCore"))
	if got := countMarkers(noBlink, blinkV8Markers, 2); got != 0 {
		t.Errorf("expected 0 Blink/V8 markers for WebKit app, got %d", got)
	}
}

func TestCountCEFForkMarkers(t *testing.T) {
	// 模拟 DingTalk：有 dtcef 标记
	dtcefBin := writeFakeBinary(t, "dtcef",
		[]byte("dtcef CGraySwitch xriver libdtriver emas"))
	if got := countMarkers(dtcefBin, cefForkMarkers, cefForkThreshold); got < cefForkThreshold {
		t.Errorf("expected >= %d CEF Fork markers, got %d", cefForkThreshold, got)
	}
}

// 交叉验证场景：DingTalk 有 CEF fork 标记 + WebKit，但没有 Blink/V8
// 这是检测器应该排除的场景
func TestDingTalkScenarioExclusion(t *testing.T) {
	// DingTalk 主程序的特征
	dingtalkBin := writeFakeBinary(t, "DingTalk",
		[]byte("dtcef CGraySwitch xriver libdtriver emas xbase_cr WKWebView JSCContext JavaScriptCore Chrome/72.0.3626.121 Safari/537.36"))

	// 有 CEF fork 标记
	cefForkCount := countMarkers(dingtalkBin, cefForkMarkers, cefForkThreshold)
	if cefForkCount < cefForkThreshold {
		t.Fatalf("expected CEF fork markers, got %d", cefForkCount)
	}

	// 有 WebKit 证据
	webkitCount := countMarkers(dingtalkBin, webkitMarkers, 2)
	if webkitCount < 2 {
		t.Fatalf("expected WebKit markers, got %d", webkitCount)
	}

	// 没有 Blink/V8 证据（关键）
	blinkCount := countMarkers(dingtalkBin, blinkV8Markers, 2)
	if blinkCount != 0 {
		t.Errorf("expected 0 Blink/V8 markers for WebKit app, got %d", blinkCount)
	}

	// Chrome 版本来自 UA
	if !findChromeVersionInUA([]byte("Chrome/72.0.3626.121 Safari/537.36")) {
		t.Error("expected Chrome version to be in UA context")
	}
}

// 交叉验证场景：真实 CEF 应用有 CEF 标记 + Blink/V8
func TestRealCEFScenarioInclusion(t *testing.T) {
	// 真实 CEF 应用特征
	cefBin := writeFakeBinary(t, "real_cef",
		[]byte("cef_ CefBrowser CefContext CefSettings CefRequestContext CefResourceRequestHandler CefLifeSpanHandler CefLoadHandler CefDisplayHandler CefRequestHandler CefClient CefApp CefV8 blink::RenderView v8::Isolate content::WebContents Chrome/118.0.5993.54"))

	// 有 CEF 标记
	cefCount := countMarkers(cefBin, cefMarkers, cefThreshold)
	if cefCount < cefThreshold {
		t.Fatalf("expected CEF markers, got %d", cefCount)
	}

	// 有 Blink/V8 证据
	blinkCount := countMarkers(cefBin, blinkV8Markers, 2)
	if blinkCount < 2 {
		t.Errorf("expected Blink/V8 markers, got %d", blinkCount)
	}
}

// 测试 Squirrel release feed 解析（Electron 自动更新格式）
func TestResolveReleaseFeed(t *testing.T) {
	// 模拟 Claude 的 RELEASES.json
	feedJSON := `{
		"releases": [
			{"updateTo": {"url": "https://downloads.claude.ai/releases/darwin/universal/1.17282.0/Claude-abc123.zip", "version": "1.17282.0"}},
			{"updateTo": {"url": "https://downloads.claude.ai/releases/darwin/universal/1.15000.0/Claude-old.zip", "version": "1.15000.0"}}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(feedJSON))
	}))
	defer srv.Close()

	url, ver, err := resolveReleaseFeed(srv.URL)
	if err != nil {
		t.Fatalf("resolveReleaseFeed failed: %v", err)
	}
	if ver != "1.17282.0" {
		t.Errorf("expected version 1.17282.0, got %s", ver)
	}
	if url != "https://downloads.claude.ai/releases/darwin/universal/1.17282.0/Claude-abc123.zip" {
		t.Errorf("unexpected url: %s", url)
	}
}

// 测试 release feed 的相对 URL 解析
func TestResolveReleaseFeedRelativeURL(t *testing.T) {
	feedJSON := `{
		"releases": [
			{"updateTo": {"url": "1.17282.0/Claude-abc123.zip", "version": "1.17282.0"}}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(feedJSON))
	}))
	defer srv.Close()

	url, ver, err := resolveReleaseFeed(srv.URL)
	if err != nil {
		t.Fatalf("resolveReleaseFeed failed: %v", err)
	}
	if ver != "1.17282.0" {
		t.Errorf("expected version 1.17282.0, got %s", ver)
	}
	// 相对 URL 应该被拼接成完整 URL
	expected := srv.URL + "/1.17282.0/Claude-abc123.zip"
	if url != expected {
		t.Errorf("expected %s, got %s", expected, url)
	}
}
