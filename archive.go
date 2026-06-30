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

	format := detectFormat(archivePath)
	fmt.Fprintf(os.Stderr, "[archive] format=%s file=%s\n", format, filepath.Base(archivePath))

	switch format {
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
	// 优先尝试 apfs-fuse（支持 APFS 磁盘镜像）
	if _, err := exec.LookPath("apfs-fuse"); err == nil {
		if err := extractDmgApfsFuse(dmgPath, destDir); err == nil {
			return nil
		}
	}

	// 回退到 7z（支持 HFS+ DMG 或 XZ 压缩的磁盘镜像）
	for _, tool := range []string{"7z", "7za", "7zr"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		cmd := exec.Command(tool, "x", dmgPath, "-o"+destDir, "-y")
		output, err := cmd.CombinedOutput()

		// 7z 提取后检查：如果产物是原始磁盘镜像（非 .app），需要进一步提取 APFS
		entries, _ := os.ReadDir(destDir)
		hasRawDisk := false
		for _, e := range entries {
		 fullPath := filepath.Join(destDir, e.Name())
		 if !e.IsDir() && !strings.HasSuffix(e.Name(), ".app") {
			 if info, err := os.Stat(fullPath); err == nil && info.Size() > 1024*1024 {
				 if apfsErr := extractAPFSFromDiskImage(fullPath, destDir); apfsErr == nil {
					 os.Remove(fullPath)
					 return nil
				 }
				 hasRawDisk = true
			 }
		 }
		}

		if err != nil && !hasRawDisk {
			outStr := string(output)
			if strings.Contains(outStr, "Dangerous link path") || strings.Contains(outStr, "Sub items Errors") {
				if entries, derr := os.ReadDir(destDir); derr == nil && len(entries) > 0 {
					return nil
				}
			}
			return fmt.Errorf("%s: %w\n%s", tool, err, output)
		}
		return nil
	}
	return fmt.Errorf("7z not found — install p7zip to extract DMG on %s", runtime.GOOS)
}

// extractAPFSFromDiskImage 从原始磁盘镜像中提取 APFS 分区内容
func extractAPFSFromDiskImage(diskImage, destDir string) error {
	mountPoint, err := os.MkdirTemp("", "hunter-apfs-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mountPoint)

	// 直接用 apfs-fuse 挂载（支持 APFS 分区和完整磁盘镜像）
	cmd := exec.Command("apfs-fuse", "-o", "ro", diskImage, mountPoint)
	if _, err := cmd.CombinedOutput(); err == nil {
		defer func() {
			if _, err := exec.LookPath("fusermount3"); err == nil {
				exec.Command("fusermount3", "-u", mountPoint).Run()
			} else {
				exec.Command("fusermount", "-u", mountPoint).Run()
			}
		}()
		return copyDirContents(mountPoint, destDir)
	}

	return fmt.Errorf("APFS extraction failed")
}

// extractDmgApfsFuse 用 apfs-fuse 挂载 APFS DMG 并复制内容
func extractDmgApfsFuse(dmgPath, destDir string) error {
	mountPoint, err := os.MkdirTemp("", "hunter-apfs-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mountPoint)

	cmd := exec.Command("apfs-fuse", "-o", "ro", dmgPath, mountPoint)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apfs-fuse: %w\n%s", err, output)
	}

	defer func() {
		if _, err := exec.LookPath("fusermount3"); err == nil {
			exec.Command("fusermount3", "-u", mountPoint).Run()
		} else {
			exec.Command("fusermount", "-u", mountPoint).Run()
		}
	}()

	return copyDirContents(mountPoint, destDir)
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
	maxDepth := 8
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
		// 收集所有 .app（含嵌套的 WeChatAppEx.app 等），不 SkipDir
		if d.IsDir() && strings.HasSuffix(path, ".app") {
			apps = append(apps, path)
		}
		return nil
	})
	return apps
}
