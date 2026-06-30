package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// SQLite 持久化层
//
// 设计：
//   scans 表 — 一次 scan/inspect-list 调用对应一行（扫描批次）
//   apps  表 — 每个检测到的应用，外键关联 scan_id
//
// 查询通过 view latest_apps 自动取每个应用最新一次扫描结果。
// ---------------------------------------------------------------------------

const schemaSQL = `
CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time            TEXT    NOT NULL,
    platform             TEXT    NOT NULL,
    source               TEXT    NOT NULL,
    scope                TEXT    NOT NULL,
    total_apps           INTEGER NOT NULL DEFAULT 0,
    with_chromium_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS apps (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL,
    name              TEXT    NOT NULL,
    app_version       TEXT,
    path              TEXT,
    bundle_id         TEXT,
    framework         TEXT    NOT NULL,
    framework_name    TEXT,
    detection         TEXT,
    chromium_version  TEXT,
    electron_version  TEXT,
    cef_version       TEXT,
    extraction_method TEXT,
    binary_path       TEXT,
    created_at        TEXT    NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_apps_scan_id     ON apps(scan_id);
CREATE INDEX IF NOT EXISTS idx_apps_name        ON apps(name);
CREATE INDEX IF NOT EXISTS idx_apps_chromium    ON apps(chromium_version);
CREATE INDEX IF NOT EXISTS idx_apps_framework   ON apps(framework);
CREATE INDEX IF NOT EXISTS idx_apps_bundle_id   ON apps(bundle_id);

-- 视图：每个应用（按名字）最新一次扫描的快照
CREATE VIEW IF NOT EXISTS latest_apps AS
SELECT a.*
FROM apps a
JOIN (
    SELECT name, MAX(scan_id) AS max_scan
    FROM apps
    GROUP BY name
) latest ON a.name = latest.name AND a.scan_id = latest.max_scan;
`

// DB 封装数据库连接
type DB struct {
	conn *sql.DB
}

// OpenDB 打开（或创建）数据库文件并确保 schema 存在
func OpenDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// 启用 WAL 模式提升并发写入
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Exec("PRAGMA foreign_keys=ON"); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Exec(schemaSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// Migration: 为旧数据库添加 app_version 列
	if err := migrateAppVersion(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate app_version: %w", err)
	}
	return &DB{conn: conn}, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

// migrateAppVersion 检查 apps 表是否有 app_version 列，没有则添加（兼容旧 DB）
func migrateAppVersion(conn *sql.DB) error {
	rows, err := conn.Query("PRAGMA table_info(apps)")
	if err != nil {
		return err
	}
	hasCol := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "app_version" {
			hasCol = true
		}
	}
	rows.Close()
	if !hasCol {
		_, err := conn.Exec("ALTER TABLE apps ADD COLUMN app_version TEXT")
		return err
	}
	return nil
}

// InsertScan 插入一次扫描批次及其所有应用记录
func (d *DB) InsertScan(result ScanResult) (int64, error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)

	// 1. 插入 scans 行
	scanRes, err := tx.Exec(
		`INSERT INTO scans (scan_time, platform, source, scope, total_apps, with_chromium_version)
		 VALUES (?,?,?,?,?,?)`,
		result.ScanTime, result.Platform, result.Source, result.Scope,
		result.Total, result.WithCVER,
	)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	scanID, err := scanRes.LastInsertId()
	if err != nil {
		return 0, err
	}

	// 2. 批量插入 apps
	stmt, err := tx.Prepare(
		`INSERT INTO apps
		   (scan_id, name, app_version, path, bundle_id, framework, framework_name,
		    detection, chromium_version, electron_version, cef_version,
		    extraction_method, binary_path, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
	)
	if err != nil {
		return 0, fmt.Errorf("prepare apps insert: %w", err)
	}
	defer stmt.Close()

	for _, app := range result.Apps {
		bundleID := readPlistBundleIDSafe(app.Path)
		if _, err := stmt.Exec(
			scanID, app.Name, app.AppVersion, app.Path, bundleID,
			string(app.Framework), app.FrameworkName,
			string(app.Detection), app.ChromiumVersion,
			app.ElectronVersion, app.CEFVersion,
			string(app.ExtractionMethod), app.BinaryPath, now,
		); err != nil {
			return 0, fmt.Errorf("insert app %s: %w", app.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return scanID, nil
}

// AppRow 查询结果行
type AppRow struct {
	ScanID           int64  `json:"scan_id"`
	Name             string `json:"app_name"`
	AppVersion       string `json:"app_version,omitempty"`
	Path             string `json:"app_path"`
	BundleID         string `json:"bundle_id,omitempty"`
	Framework        string `json:"framework"`
	FrameworkName    string `json:"framework_name,omitempty"`
	Detection        string `json:"detection,omitempty"`
	ChromiumVersion  string `json:"chromium_version,omitempty"`
	ElectronVersion  string `json:"electron_version,omitempty"`
	CEFVersion       string `json:"cef_version,omitempty"`
	ExtractionMethod string `json:"extraction_method,omitempty"`
	BinaryPath       string `json:"binary_path,omitempty"`
	ScanTime         string `json:"scan_time,omitempty"`
}

// QueryLatest 返回所有应用的最新快照
func (d *DB) QueryLatest() ([]AppRow, error) {
	rows, err := d.conn.Query(
		`SELECT a.name, a.app_version, a.path, a.bundle_id, a.framework, a.framework_name,
		        a.detection, a.chromium_version, a.electron_version, a.cef_version,
		        a.extraction_method, a.binary_path, s.scan_time
		 FROM latest_apps a
		 JOIN scans s ON a.scan_id = s.id
		 ORDER BY a.name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppRows(rows)
}

// QueryByName 返回某应用的所有历史扫描记录
func (d *DB) QueryByName(name string) ([]AppRow, error) {
	rows, err := d.conn.Query(
		`SELECT a.name, a.app_version, a.path, a.bundle_id, a.framework, a.framework_name,
		        a.detection, a.chromium_version, a.electron_version, a.cef_version,
		        a.extraction_method, a.binary_path, s.scan_time
		 FROM apps a
		 JOIN scans s ON a.scan_id = s.id
		 WHERE a.name LIKE ?
		 ORDER BY s.scan_time DESC`,
		"%"+name+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppRows(rows)
}

// QueryByChromium 返回使用特定 Chromium 版本范围的所有应用
func (d *DB) QueryByChromium(minMajor, maxMajor int) ([]AppRow, error) {
	rows, err := d.conn.Query(
		`SELECT a.name, a.app_version, a.path, a.bundle_id, a.framework, a.framework_name,
		        a.detection, a.chromium_version, a.electron_version, a.cef_version,
		        a.extraction_method, a.binary_path, s.scan_time
		 FROM latest_apps a
		 JOIN scans s ON a.scan_id = s.id
		 WHERE CAST(substr(a.chromium_version, 1, instr(a.chromium_version, '.') - 1) AS INTEGER) BETWEEN ? AND ?
		 ORDER BY a.chromium_version`,
		minMajor, maxMajor,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAppRows(rows)
}

// ScanStats 返回扫描统计信息
type ScanStats struct {
	TotalScans       int     `json:"total_scans"`
	TotalApps        int     `json:"total_unique_apps"`
	OldestChromium   string  `json:"oldest_chromium"`
	NewestChromium   string  `json:"newest_chromium"`
	LastScanTime     string  `json:"last_scan_time"`
	FrameworkBreakdown map[string]int `json:"framework_breakdown"`
}

// QueryStats 返回数据库统计信息
func (d *DB) QueryStats() (*ScanStats, error) {
	stats := &ScanStats{FrameworkBreakdown: make(map[string]int)}

	// 总扫描次数
	d.conn.QueryRow("SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans)
	// 唯一应用数
	d.conn.QueryRow("SELECT COUNT(DISTINCT name) FROM apps").Scan(&stats.TotalApps)
	// 最新扫描时间
	d.conn.QueryRow("SELECT MAX(scan_time) FROM scans").Scan(&stats.LastScanTime)
	// 最旧/最新 Chromium
	d.conn.QueryRow(
		`SELECT chromium_version FROM latest_apps
		 WHERE chromium_version != ''
		 ORDER BY CAST(substr(chromium_version,1,instr(chromium_version,'.')-1) AS INTEGER) ASC
		 LIMIT 1`,
	).Scan(&stats.OldestChromium)
	d.conn.QueryRow(
		`SELECT chromium_version FROM latest_apps
		 WHERE chromium_version != ''
		 ORDER BY CAST(substr(chromium_version,1,instr(chromium_version,'.')-1) AS INTEGER) DESC
		 LIMIT 1`,
	).Scan(&stats.NewestChromium)

	// 框架分布
	rows, err := d.conn.Query(
		`SELECT framework, COUNT(*) FROM latest_apps GROUP BY framework`,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var fw string
			var n int
			rows.Scan(&fw, &n)
			stats.FrameworkBreakdown[fw] = n
		}
	}

	return stats, nil
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

func scanAppRows(rows *sql.Rows) ([]AppRow, error) {
	var result []AppRow
	for rows.Next() {
		var r AppRow
		var appVer, path, bundleID, fwName, detection, chrome, electron, cef, method, binPath, scanTime sql.NullString
		if err := rows.Scan(
			&r.Name, &appVer, &path, &bundleID, &r.Framework, &fwName,
			&detection, &chrome, &electron, &cef, &method, &binPath, &scanTime,
		); err != nil {
			return nil, err
		}
		r.AppVersion = appVer.String
		r.Path = path.String
		r.BundleID = bundleID.String
		r.FrameworkName = fwName.String
		r.Detection = detection.String
		r.ChromiumVersion = chrome.String
		r.ElectronVersion = electron.String
		r.CEFVersion = cef.String
		r.ExtractionMethod = method.String
		r.BinaryPath = binPath.String
		r.ScanTime = scanTime.String
		result = append(result, r)
	}
	return result, rows.Err()
}

// readPlistBundleIDSafe 安全读取 bundle ID（非 macOS 或不存在时返回空）
func readPlistBundleIDSafe(appPath string) string {
	if appPath == "" {
		return ""
	}
	return readPlistBundleID(filepath.Join(appPath, "Contents", "Info.plist"))
}
