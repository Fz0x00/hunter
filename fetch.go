package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func downloadFile(url, destDir string, timeout time.Duration) (string, error) {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", err
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) hunter/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	filename := guessFilename(url, resp)
	destPath := filepath.Join(destDir, filename)

	out, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "[fetch] %s (%s)\n", filename, humanBytes(written))
	return destPath, nil
}

func guessFilename(url string, resp *http.Response) string {
	decoded := url
	if resp.Request != nil && resp.Request.URL != nil {
		decoded = resp.Request.URL.String()
	}
	if name := filepath.Base(decoded); name != "" && name != "/" && !strings.Contains(name, "?") {
		return sanitizeFilename(name)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if idx := strings.Index(cd, "filename="); idx >= 0 {
			name := strings.Trim(cd[idx+9:], `"`)
			return sanitizeFilename(name)
		}
	}
	return "download.bin"
}

func sanitizeFilename(s string) string {
	s = strings.SplitN(s, "?", 2)[0]
	for _, ch := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"} {
		s = strings.ReplaceAll(s, ch, "_")
	}
	return s
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
