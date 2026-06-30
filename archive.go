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
	default:
		return fmt.Errorf("unsupported archive format: %s", archivePath)
	}
}

func detectFormat(path string) string {
	name := strings.ToLower(filepath.Base(path))
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

	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		return "zip"
	}
	if len(data) >= 512 && string(data[0:4]) == "koly" {
		return "dmg"
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
