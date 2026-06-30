package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func extractArchive(archivePath, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	switch detectFormat(archivePath) {
	case "zip":
		return extractZip(archivePath, destDir)
	case "dmg":
		return extractDmg(archivePath, destDir)
	case "pkg":
		return extractPkg(archivePath, destDir)
	case "xz":
		return extractCompressed(archivePath, destDir, "xz")
	case "gz":
		return extractCompressed(archivePath, destDir, "gz")
	case "7z":
		return extractCompressed(archivePath, destDir, "7z")
	default:
		return fmt.Errorf("unsupported archive format: %s", archivePath)
	}
}

func detectFormat(path string) string {
	name := strings.ToLower(filepath.Base(path))

	// 扩展名检测优先（.dmg/.pkg 扩展名优先于 magic bytes）
	// 微信 DMG 的头部恰好是 XZ magic，但实际是标准 DMG 格式
	switch {
	case strings.HasSuffix(name, ".zip"):
		return "zip"
	case strings.HasSuffix(name, ".dmg"):
		return "dmg"
	case strings.HasSuffix(name, ".pkg"):
		return "pkg"
	case strings.HasSuffix(name, ".exe"), strings.HasSuffix(name, ".msi"):
		return "exe"
	}

	// Magic byte 检测（扩展名无法识别时）
	head := make([]byte, 6)
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if n, _ := f.Read(head); n >= 4 {
		// ZIP: "PK\x03\x04"
		if string(head[:4]) == "PK\x03\x04" {
			return "zip"
		}
		// XZ: "\xfd7zXZ"
		if string(head[:6]) == "\xfd\x37\x7a\x58\x5a\x00" {
			return "xz"
		}
		// GZ: "\x1f\x8b"
		if head[0] == 0x1f && head[1] == 0x8b {
			return "gz"
		}
		// 7z: "7z\xbc\xaf\x27\x1c"
		if string(head[:6]) == "7z\xbc\xaf\x27\x1c" {
			return "7z"
		}
	}

	// DMG trailer check (only for files without extension)
	fi, _ := f.Stat()
	if fi.Size() >= 512 {
		tail := make([]byte, 512)
		if _, err := f.ReadAt(tail, fi.Size()-512); err == nil {
			if string(tail[0:4]) == "koly" {
				return "dmg"
			}
		}
	}
	return ""
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}

func extractDmg(dmgPath, destDir string) error {
	switch runtime.GOOS {
	case "darwin":
		return extractDmgMac(dmgPath, destDir)
	default:
		return extractDmg7z(dmgPath, destDir)
	}
}

func extractDmgMac(dmgPath, destDir string) error {
	mountPoint, err := os.MkdirTemp("", "hunter-dmg-*")
	if err != nil {
		return err
	}
	os.Chmod(mountPoint, 0755)
	defer func() {
		exec.Command("hdiutil", "detach", mountPoint, "-force").Run()
		os.RemoveAll(mountPoint)
	}()

	cmd := exec.Command("hdiutil", "attach", "-nobrowse", "-mountpoint", mountPoint, dmgPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("hdiutil attach: %w\n%s", err, output)
	}

	return copyDirContents(mountPoint, destDir)
}

func extractDmg7z(dmgPath, destDir string) error {
	for _, tool := range []string{"7z", "7za", "7zr"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		cmd := exec.Command(tool, "x", dmgPath, "-o"+destDir, "-y")
		output, err := cmd.CombinedOutput()
		if err != nil {
			// 7z 对 DMG 里的 /Applications 符号链接会报 "Dangerous link path"
			// 但 .app 本身已经提取成功，检查目标目录是否有内容即可
			outStr := string(output)
			if strings.Contains(outStr, "Dangerous link path") || strings.Contains(outStr, "Sub items Errors") {
				if entries, derr := os.ReadDir(destDir); derr == nil && len(entries) > 0 {
					return nil // 文件已提取，符号链接跳过是 OK 的
				}
			}
			return fmt.Errorf("%s: %w\n%s", tool, err, output)
		}
		return nil
	}
	return fmt.Errorf("7z not found — install p7zip to extract DMG on %s", runtime.GOOS)
}

func extractPkg(pkgPath, destDir string) error {
	tmpExpand, err := os.MkdirTemp("", "hunter-pkg-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpExpand)

	if runtime.GOOS == "darwin" {
		cmd := exec.Command("pkgutil", "--expand-full", pkgPath, tmpExpand)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("pkgutil: %w\n%s", err, output)
		}
	} else {
		return extractDmg7z(pkgPath, destDir)
	}

	return copyDirContents(tmpExpand, destDir)
}

func copyDirContents(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		s := filepath.Join(src, entry.Name())
		d := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			os.MkdirAll(d, 0755)
			copyDirContents(s, d)
		} else {
			data, err := os.ReadFile(s)
			if err != nil {
				continue
			}
			os.MkdirAll(filepath.Dir(d), 0755)
			os.WriteFile(d, data, 0644)
		}
	}
	return nil
}

// extractCompressed extracts XZ/GZ/7z archives, then recursively extracts the inner archive if needed
func extractCompressed(archivePath, destDir string, format string) error {
	// Step 1: Decompress to get the inner file
	var cmd *exec.Cmd
	switch format {
	case "xz":
		// xz requires .xz suffix, use -c to decompress to stdout
		// Note: xz may return exit code 1 for multi-stream files even on success
		outFile := strings.TrimSuffix(archivePath, filepath.Ext(archivePath))
		cmd = exec.Command("sh", "-c", fmt.Sprintf("xz -dc %q > %q; test -s %q", archivePath, outFile, outFile))
	case "gz":
		outFile := strings.TrimSuffix(archivePath, filepath.Ext(archivePath))
		cmd = exec.Command("sh", "-c", fmt.Sprintf("gzip -dc %q > %q; test -s %q", archivePath, outFile, outFile))
	case "7z":
		for _, tool := range []string{"7z", "7za", "7zr"} {
			if _, err := exec.LookPath(tool); err == nil {
				cmd = exec.Command(tool, "x", archivePath, "-o"+destDir, "-y")
				if output, err := cmd.CombinedOutput(); err != nil {
					outStr := string(output)
					if strings.Contains(outStr, "Dangerous link path") || strings.Contains(outStr, "Sub items Errors") {
						if entries, derr := os.ReadDir(destDir); derr == nil && len(entries) > 0 {
							return nil // partial success
						}
					}
					return fmt.Errorf("7z extract: %w", err)
				}
				return nil
			}
		}
		return fmt.Errorf("7z not found")
	}

	// For xz/gz: decompress to same directory, producing a file without the compression extension
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s decompress: %w\n%s", format, err, output)
	}

	// Step 2: Find the decompressed file (same name without .xz/.gz extension)
	decompressedPath := strings.TrimSuffix(archivePath, "."+format)
	if _, err := os.Stat(decompressedPath); err != nil {
		return fmt.Errorf("decompressed file not found: %s", decompressedPath)
	}

	// Step 3: Recursively extract the inner archive
	return extractArchive(decompressedPath, destDir)
}

func findAppsInDir(root string) []string {
	var apps []string
	maxDepth := 6
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() && strings.HasSuffix(path, ".app") {
			apps = append(apps, path)
			return filepath.SkipDir
		}
		return nil
	})
	return apps
}
