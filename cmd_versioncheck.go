package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// versionsFile 跟踪每个应用上次检测到的版本签名（URL/tag）
type versionsFile struct {
	Updated string                    `json:"updated"`
	Apps    map[string]versionEntry   `json:"apps"`
}

type versionEntry struct {
	URL     string `json:"url"`
	Tag     string `json:"tag,omitempty"`
	Checked string `json:"checked"`
}

// versionSignature 返回用于比较的版本签名：优先 tag，否则用 URL
func (v versionEntry) signature() string {
	if v.Tag != "" {
		return v.Tag
	}
	return v.URL
}

func runVersionCheck(args []string) {
	fs := flag.NewFlagSet("version-check", flag.ExitOnError)
	var (
		dynamicURLFile string
		output         string
		platformFilter string
	)
	fs.StringVar(&dynamicURLFile, "dynamic-urls", "", "path to dynamic-urls.json")
	fs.StringVar(&output, "output", "versions.json", "path to versions.json (read+write)")
	fs.StringVar(&platformFilter, "platform", "", "filter: macos|linux|any (empty=all)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: hunter version-check <apps.json>")
		os.Exit(1)
	}

	reg, err := loadRegistry(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if dynamicURLFile != "" {
		loadDynamicURLs(dynamicURLFile)
	}

	// 加载旧版本
	var old versionsFile
	if data, err := os.ReadFile(output); err == nil {
		json.Unmarshal(data, &old)
	}
	if old.Apps == nil {
		old.Apps = map[string]versionEntry{}
	}

	platformOK := func(e AppEntry) bool {
		if platformFilter == "" {
			return true
		}
		if platformFilter == "macos" {
			return e.Platform == "macos"
		}
		if platformFilter == "linux" {
			return e.Platform != "macos"
		}
		return true
	}

	// 解析所有 URL，提取版本签名
	type resolved struct {
		entry AppEntry
		url   string
		tag   string
		err   error
	}

	var all []resolved
	for _, entry := range reg.Apps {
		if !platformOK(entry) {
			continue
		}
		r := resolved{entry: entry}
		r.url, r.tag, r.err = entry.resolveDownloadURL()
		all = append(all, r)
	}

	// 对比，找出变更
	var changed []string
	var failed []string
	now := time.Now().UTC().Format(time.RFC3339)
	newApps := map[string]versionEntry{}

	for _, r := range all {
		if r.err != nil {
			failed = append(failed, r.entry.Name)
			fmt.Fprintf(os.Stderr, "[skip] %s: %v\n", r.entry.Name, r.err)
			// 保留旧记录
			if old, ok := old.Apps[r.entry.Name]; ok {
				newApps[r.entry.Name] = old
			}
			continue
		}

		entry := versionEntry{URL: r.url, Tag: r.tag, Checked: now}
		newApps[r.entry.Name] = entry

		oldEntry, existed := old.Apps[r.entry.Name]
		if !existed {
			changed = append(changed, r.entry.Name)
			fmt.Fprintf(os.Stderr, "[NEW] %s: %s\n", r.entry.Name, r.tag)
		} else if entry.signature() != oldEntry.signature() {
			changed = append(changed, r.entry.Name)
			fmt.Fprintf(os.Stderr, "[CHANGED] %s: %s -> %s\n", r.entry.Name, oldEntry.signature(), entry.signature())
		} else {
			fmt.Fprintf(os.Stderr, "[ok] %s: %s\n", r.entry.Name, entry.signature())
		}
	}

	// 写入 versions.json
	out := versionsFile{Updated: now, Apps: newApps}
	data, _ := json.MarshalIndent(out, "", "  ")
	data = append(data, '\n')
	os.WriteFile(output, data, 0644)
	fmt.Fprintf(os.Stderr, "\n[version-check] %d apps checked, %d changed, %d failed\n",
		len(all), len(changed), len(failed))

	// 输出变更的 app 名（逗号分隔，供 workflow 使用）
	// 格式: CHANGED=App1,App2,App3
	fmt.Printf("CHANGED=%s\n", strings.Join(changed, ","))
}
