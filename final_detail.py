# -*- coding: utf-8 -*-
"""final_detail.py — 纯协议获取商品详情（无浏览器、无签名）

实测结论（2026-09-26）：
  `POST https://api.cdfsunrise.com/restapi/search/item/v3` **不在阿里云 WAF
  的强校验路径名单内** —— 裸 requests 直接 POST 即返回 200 真实 JSON，
  URL 上不需要 `md5__1803` 签名参数（16/16 次实测全部放行）。

  对比：`POST /restapi/search/list`（商品列表）被强校验，无签名必然返回
  110310 字节挑战 HTML，必须走 `final_step3_v3.py` 的 iv8_rs 签名链路。
  本脚本因此只需 requests —— 这是最纯粹的「纯协议」形态。

请求体（从商详组件 chunk 7972 反编译确认）：
  {"goodsId": "...", "purchaseType": "1",
   "showLoading": true, "priceExp": true}

用法：
  python -X utf8 final_detail.py [goodsId] [输出文件]

  python -X utf8 final_detail.py
  python -X utf8 final_detail.py 69dc9e53e79f9c0001d9001a
  python -X utf8 final_detail.py 69dc9e53e79f9c0001d9001a my_detail.json

输出：
  detail_item_v3.json   商品详情 JSON 全文（默认文件名，可用第 2 个参数改）
  final_detail_log.txt  运行日志
"""
import json
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import requests

ITEM_API = "https://api.cdfsunrise.com/restapi/search/item/v3"
DEFAULT_GOODS_ID = "69dc9e53e79f9c0001d9001a"
DEFAULT_OUT = "detail_item_v3.json"
LOG_FILE = "final_detail_log.txt"

# 注意：不覆盖 User-Agent 为浏览器 UA 之外的值；此处用 Firefox UA 与
# final_step3_v3.py 保持一致（该接口不做 UA/sec-ch-ua 一致性校验）。
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) "
      "Gecko/20100101 Firefox/152.0")

HEADERS = {
    "Content-Type": "application/json;charset=UTF-8",
    "usersystem": "h5platform",
    "miniapp": "h5",
    "appversion": "1.60.0",
    "clientnetwork": "unknown",
    "mobile": "",
    "accesstoken": "",
    "device": "",
    "deviceid": "",
    "openid": "",
    "alipayopenid": "",
    "unionid": "",
    "User-Agent": UA,
    "Origin": "https://h5.cdfsunrise.com",
    "Referer": "https://h5.cdfsunrise.com/",
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
}


def pylog(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def build_body(goods_id):
    return {
        "goodsId": goods_id,
        "purchaseType": "1",
        "showLoading": True,
        "priceExp": True,
    }


def is_challenge(resp):
    """判定是否被 WAF 挑战（该接口正常应返回 application/json）"""
    ct = resp.headers.get("content-type", "")
    if "json" in ct:
        return False
    return ("text/html" in ct) or ("renderData" in resp.text[:2000])


def main():
    goods_id = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GOODS_ID
    out_file = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("final_detail start %s goodsId=%s\n"
                % (time.strftime("%H:%M:%S"), goods_id))

    body = build_body(goods_id)
    body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    pylog("goodsId=%s" % goods_id)
    pylog("body=%s" % body_str)

    session = requests.Session()
    session.headers.update(HEADERS)

    pylog("== POST %s ==" % ITEM_API)
    r = session.post(ITEM_API, data=body_str.encode("utf-8"), timeout=20)
    ct = r.headers.get("content-type", "")
    pylog("  status=%s len=%s ct=%s server=%s"
          % (r.status_code, len(r.content), ct,
             r.headers.get("server", "")))

    if r.status_code != 200 or is_challenge(r):
        pylog("[!] 未拿到 JSON —— 该接口可能已被 WAF 升级为强校验")
        pylog("    响应头 200 字节预览: %s" % r.text[:200].replace("\n", " "))
        pylog("    若确为挑战页, 需改用 final_step3_v3.py 的 iv8_rs 签名链路")
        return 1

    try:
        data = r.json()
    except Exception as e:
        pylog("[!] JSON 解析失败: %r" % e)
        return 1

    gd = data.get("goodsDetail") or {}
    pylog("  商品名 : %s" % gd.get("goodsName"))
    pylog("  品牌   : %s / %s"
          % (gd.get("chineseBrandName"), gd.get("englishBrandName")))
    pylog("  价格   : %s  券后: %s  指导价: %s"
          % ((gd.get("price") or {}).get("price"),
             (gd.get("buyPrice") or {}).get("price"),
             (gd.get("standardPrice") or {}).get("price")))
    pylog("  库存   : stock=%s availableStock=%s"
          % (gd.get("stock"), gd.get("availableStock")))
    pylog("  商家   : %s (%s)" % (gd.get("merchantName"),
                                  gd.get("merchantID")))
    pylog("  好评率 : %s" % (data.get("comment") or {}).get("commentValue"))

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    pylog("★★★★★ 成功 → %s" % out_file)
    pylog("final_detail DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
