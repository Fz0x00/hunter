package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	semverRe      = regexp.MustCompile(`^\d+\.\d+\.\d+`)
	xmlVersionRe  = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>`)
	xmlBundleIDRe = regexp.MustCompile(`<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>`)
)

func readElectronVersionFromApp(appPath, fwDir string) string {
	for _, p := range []string{
		filepath.Join(fwDir, "Versions", "A", "Resources", "Info.plist"),
		filepath.Join(fwDir, "Versions", "Current", "Resources", "Info.plist"),
		filepath.Join(appPath, "Contents", "Info.plist"),
	} {
		if v := readPlistField(p, "CFBundleShortVersionString"); v != "" {
			if m := semverRe.FindString(v); m != "" {
				return m
			}
		}
	}
	return ""
}

func readPlistBundleID(path string) string {
	return readPlistField(path, "CFBundleIdentifier")
}

func readPlistField(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if isXMLPlist(data) {
		return readXMLField(data, key)
	}
	if isBinaryPlist(data) {
		return scanBinaryField(data, key)
	}
	return ""
}

func isXMLPlist(data []byte) bool {
	return bytes.HasPrefix(data, []byte("<?xml")) || bytes.HasPrefix(data, []byte("<plist"))
}

func isBinaryPlist(data []byte) bool {
	return bytes.HasPrefix(data, []byte("bplist"))
}

func readXMLField(data []byte, key string) string {
	var re *regexp.Regexp
	switch key {
	case "CFBundleShortVersionString":
		re = xmlVersionRe
	case "CFBundleIdentifier":
		re = xmlBundleIDRe
	default:
		re = regexp.MustCompile(regexp.QuoteMeta("<key>"+key+"</key>") + `\s*<string>([^<]+)</string>`)
	}
	m := re.FindSubmatch(data)
	if len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

func scanBinaryField(data []byte, key string) string {
	marker := []byte(key)
	idx := bytes.Index(data, marker)
	if idx < 0 {
		return ""
	}
	tail := data[idx+len(marker):]
	end := len(tail)
	if end > 256 {
		end = 256
	}
	for _, field := range bytes.Fields(tail[:end]) {
		cleaned := strings.Trim(string(field), "\x00\x10\x12\x16\x17\x1f\"' ")
		if cleaned == "" {
			continue
		}
		if key == "CFBundleShortVersionString" {
			// 返回原始值，由调用方决定是否过滤
			if isASCII(cleaned) {
				return cleaned
			}
		} else if key == "CFBundleIdentifier" {
			if isASCII(cleaned) && strings.Contains(cleaned, ".") && len(cleaned) > 6 {
				return cleaned
			}
		}
	}
	return ""
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}
