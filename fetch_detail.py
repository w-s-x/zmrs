# -*- coding: utf-8 -*-
"""商品详情页被动收割 — 复用 recycle/fetch_goods.py 已验证方案

原理: 驱动真实 Edge 二进制(channel="msedge")打开详情页,
让页面自己的 WAF 层生成签名并发出请求, Python 只被动收割响应.
不覆盖 UA, 不构造/重放任何请求.

用法: python fetch_detail.py <goodsId> [输出文件名]
"""
import json
import sys
import time

from playwright.sync_api import sync_playwright

def main():
    goods_id = sys.argv[1] if len(sys.argv) > 1 else "69dc9e53e79f9c0001d9001a"
    out_file = sys.argv[2] if len(sys.argv) > 2 else "detail_capture.json"
    url = ("https://h5.cdfsunrise.com/pages/main/product/subject/detail/index"
           "?goodsId=" + goods_id)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=False)
        ctx = browser.new_context(locale="zh-CN")  # 不覆盖 UA
        ctx.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        page = ctx.new_page()

        captured = []  # 所有 api.cdfsunrise.com 的 JSON 响应

        def on_response(resp):
            url_ = resp.url
            if "api.cdfsunrise.com" not in url_:
                return
            ct = resp.headers.get("content-type") or ""
            if "json" not in ct:
                return
            try:
                body = resp.text()
            except Exception:
                return
            captured.append({
                "url": url_,
                "status": resp.status,
                "len": len(body),
                "body": body,
            })
            print("[cap] %s %s len=%d" % (resp.status, url_[:120], len(body)),
                  flush=True)

        page.on("response", on_response)
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
        # 等页面发完详情请求
        deadline = time.time() + 25
        n = 0
        while time.time() < deadline:
            page.wait_for_timeout(1000)
            if len(captured) >= n and len(captured) > n:
                n = len(captured)
                # 连续 5 秒无新响应则认为抓完
            elif time.time() > deadline - 20 and len(captured) == n:
                break

        browser.close()

    # 落盘
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(captured, f, ensure_ascii=False, indent=2)
    print("DONE: %d 个 JSON 响应 → %s" % (len(captured), out_file))

    # 识别详情主接口
    for c in captured:
        if "getGoodsDetail" in c["url"]:
            print("★ 详情接口: %s (len=%d)" % (c["url"], c["len"]))

if __name__ == "__main__":
    main()
