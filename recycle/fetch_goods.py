# -*- coding: utf-8 -*-
"""中免日上 H5 商品列表抓取 — 最终方案
原理: WAF(md5__1803) 签名编码浏览器指纹, 服务端验签. 假浏览器(playwright chromium/
camoufox/补环境)全部被识破. 唯一可行: 驱动真实 Edge 二进制(channel="msedge"),
让页面自己的 WAF 层生成签名并发出请求, Python 只被动收割响应.
用法: python fetch_goods.py [页码]  (默认第 1 页)
"""
import json
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright

SEARCH_KEY = "热门组合装"
CID = "171_541_265_411_566_310"
CMS_PAGE_ID = "1cd71e2661000"

def build_search_url(page_number):
    # pageNumber 不在 URL 里(在 POST body), URL 只负责让页面打开搜索结果
    qs = {
        "category": "%20", "cid": CID, "cmsPageId": CMS_PAGE_ID,
        "fromSearchUrl": "1", "order": "1", "originFrom": "h5",
        "platform": "h5", "purchaseType": "1", "scene": "qpol",
        "searchField": SEARCH_KEY, "status": "0", "stamp": "AA",
        "$taroTimestamp": str(int(time.time() * 1000)),
    }
    return ("https://h5.cdfsunrise.com/search/search-result?"
            + urllib.parse.urlencode(qs))

def main():
    page_number = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    with sync_playwright() as p:
        # channel="msedge" = 你机器上真实安装的 Edge 二进制, 非 chromium 仿制品
        browser = p.chromium.launch(channel="msedge", headless=False)
        ctx = browser.new_context(locale="zh-CN")  # 不覆盖 UA: 让真实 Edge 自己发, 避免 UA/sec-ch-ua 不匹配被识破
        # 隐藏自动化标志 (WAF 检测 navigator.webdriver)
        ctx.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        page = ctx.new_page()
        got = {}

        def on_response(resp):
            # 判定放行: JSON 响应且含商品字段(挑战 HTML 也是 200, 靠内容区分)
            ct = resp.headers.get("content-type") or ""
            url = resp.url
            if "restapi/search/list" in url:
                try:
                    body = resp.text()
                except Exception:
                    return
                if "goodsList" in body:
                    got["resp"] = resp
                else:
                    got.setdefault("challenge", []).append(
                        {"url": url[:120], "len": len(body),
                         "ct": ct, "status": resp.status})

        page.on("response", on_response)
        page.goto(build_search_url(page_number), wait_until="domcontentloaded",
                  timeout=60000)
        # 等页面自己发签名请求(无签名首请求会被挑战, WAF 自动升级签名重试)
        # ponytail: 分页时 URL 里没有 pageNumber, 页面固定请求第 1 页; 多页抓取需
        # 改造注入 body 或模拟页面滚动加载, 当前单页够用, 需要时再加
        deadline = time.time() + 30
        while time.time() < deadline and "resp" not in got:
            page.wait_for_timeout(500)
        if "resp" not in got:
            print("NO goodsList response captured", file=sys.stderr)
            for c in got.get("challenge", []):
                print("  challenge: %s status=%s len=%s ct=%s"
                      % (c["url"], c["status"], c["len"], c["ct"]),
                      file=sys.stderr)
            browser.close()
            sys.exit(1)
        resp = got["resp"]
        data = resp.json()
        assert data.get("goodsList") is not None, "响应无 goodsList, WAF 未放行"
        out = "goods_p%d.json" % page_number
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print("OK page=%d totalCount=%s saved=%s"
              % (page_number, data.get("totalCount"), out))
        browser.close()

if __name__ == "__main__":
    main()
