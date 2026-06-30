#!/usr/bin/env python3
"""
URL 收集器：用 Playwright 无头浏览器定期获取 JS 渲染下载页面的真实下载链接。

输出 dynamic-urls.json：
{
  "updated": "2026-06-30T18:00:00Z",
  "urls": {
    "BlueStacks": "https://ak-build.bluestacks.com/...",
    "Doubao": "https://lf9-apk.ugapk.cn/...",
    "QQ": "https://qqdl.gtimg.cn/..."
  }
}

hunter inspect-list 会读取此文件，对 apps.json 里标记 "dynamic": true 的 app
使用此文件中的 URL 而非尝试解析下载页。
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from playwright.sync_api import sync_playwright

UA_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/126.0.0.0 Safari/537.36")

DL_RE = re.compile(r"https?://[^\s\"'<>]+\.(?:dmg|pkg|zip)(?:[^\s\"'<>]*)", re.IGNORECASE)

OUTPUT = Path(__file__).resolve().parent.parent / "dynamic-urls.json"


def collect_qq(page):
    """QQ: im.qq.com/mac/ 页面 DOM 里有版本化 DMG 链接"""
    print("[QQ] collecting...", flush=True)
    captured = []

    def on_resp(resp):
        if DL_RE.search(resp.url):
            captured.append(resp.url)

    page.on("response", on_resp)
    try:
        page.goto("https://im.qq.com/mac/", wait_until="domcontentloaded", timeout=25000)
    except Exception as e:
        print(f"  [QQ] goto error: {e}")
    page.wait_for_timeout(3000)

    # DOM 查找
    html = page.content()
    urls = DL_RE.findall(html)
    if urls:
        u = sorted(urls)[0]
        print(f"  [QQ] -> {u}")
        return u

    # 尝试点击下载按钮
    for sel in ["text=下载", "text=Mac", "a:has-text('下载')"]:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0 and loc.is_visible():
                loc.click(timeout=3000)
                page.wait_for_timeout(3000)
                break
        except Exception:
            pass

    if captured:
        u = sorted(set(captured))[0]
        print(f"  [QQ] (network) -> {u}")
        return u

    print("  [QQ] FAILED")
    return None


def collect_doubao(page):
    """豆包: doubao.com/download 点击下载后网络请求中出现 DMG 链接"""
    print("[Doubao] collecting...", flush=True)
    captured = []

    def on_resp(resp):
        if DL_RE.search(resp.url):
            captured.append(resp.url)

    page.on("response", on_resp)
    try:
        page.goto("https://www.doubao.com/download/", wait_until="domcontentloaded", timeout=25000)
    except Exception as e:
        print(f"  [Doubao] goto error: {e}")
    page.wait_for_timeout(3000)

    # 点击"下载"按钮
    for sel in ["text=下载", "text=Download", "text=Mac"]:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0 and loc.is_visible():
                loc.click(timeout=3000)
                page.wait_for_timeout(3000)
                break
        except Exception:
            pass

    if captured:
        u = sorted(set(captured))[0]
        print(f"  [Doubao] -> {u}")
        return u

    print("  [Doubao] FAILED")
    return None


def collect_bluestacks(page):
    """BlueStacks: bluestacks.com/download.html 点击 Download 后网络请求中出现 PKG 链接"""
    print("[BlueStacks] collecting...", flush=True)
    captured = []

    def on_resp(resp):
        if DL_RE.search(resp.url):
            captured.append(resp.url)

    page.on("response", on_resp)
    try:
        page.goto("https://www.bluestacks.com/download.html", wait_until="domcontentloaded", timeout=25000)
    except Exception as e:
        print(f"  [BlueStacks] goto error: {e}")
    page.wait_for_timeout(3000)

    # 点击 Download 按钮（可能需要先选 Mac）
    for sel in ["text=Mac", "text=Download", "text=下载"]:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0 and loc.is_visible():
                loc.click(timeout=3000)
                page.wait_for_timeout(3000)
                break
        except Exception:
            pass

    if captured:
        u = sorted(set(captured))[0]
        print(f"  [BlueStacks] -> {u}")
        return u

    print("  [BlueStacks] FAILED")
    return None


def main():
    results = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=UA_MAC, locale="zh-CN", accept_downloads=True)

        results["QQ"] = collect_qq(context.new_page())
        results["Doubao"] = collect_doubao(context.new_page())
        results["BlueStacks"] = collect_bluestacks(context.new_page())

        browser.close()

    # 合并旧数据（如果新获取失败，保留旧 URL）
    old = {}
    if OUTPUT.exists():
        try:
            old = json.loads(OUTPUT.read_text()).get("urls", {})
        except Exception:
            pass

    merged = {}
    for name, url in results.items():
        if url:
            merged[name] = url
        elif name in old:
            merged[name] = old[name]  # 保留旧链接
            print(f"  [{name}] using cached URL from previous run")

    output = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "urls": merged,
    }

    OUTPUT.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n")
    print(f"\nSaved to {OUTPUT}")
    print(json.dumps(output, indent=2, ensure_ascii=False))

    # 退出码：全部失败=1，至少一个成功=0
    if not any(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
