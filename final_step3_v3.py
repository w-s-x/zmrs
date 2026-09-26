# -*- coding: utf-8 -*-
"""Step3 v3: page_load 上下文 + 双eval + GET探路 + POST签名 → 数据

v2 失败根因: 裸 eval 缺 DOM — 签名需要挑战页 DOM 的 renderData 密钥
(每次挑战不同) + meta aliyun_waf_aa + cookie acw_tc.
Step2 已证 page_load 上下文的 GET 签名有效 (404 穿透).

v3 链路:
  1. requests Session GET API → 新挑战页 + 新 acw_tc (同 Session)
  2. 沙箱 page_load 原版挑战页 (Set-Cookie 新 acw_tc, base_url=API)
     → Lblfpo 完整跑: 读 DOM 密钥 → 指纹 → 路径C GET签名(location.href)
     → 间谍同时捕获 Lblfpo.toString() 原文
  3. useGuard=true → eval 补丁版 (Lf捕获/LK记录/fetchShim/路径B强制)
     → guard 让 toString 返回原文 → tp 自校验通过 → 正常初始化
  4. GET 探路: requests 同Session GET 路径C签名URL → 预期 404 (WAF放行)
  5. Lf(LZ POST) → LK(签名) → fetchShim → handler → requests 同Session
     POST 签名URL + 完整头套 + 精确同body → 200 JSON ★
"""
import json
import re
import sys
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import requests

API = "https://api.cdfsunrise.com/restapi/search/list"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"

LOG_FILE = "final_step3_v3_log.txt"


def pylog(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def read(name):
    with open(name, encoding="utf-8") as f:
        return f.read()


SPY_GUARD_JS = r"""
(function(){
  var W = window;
  W.__origSrc = null;
  W.__tsCalls = 0;
  var origTS = Function.prototype.toString;
  var guard = function(){
    W.__tsCalls++;
    var s;
    try { s = origTS.call(this); } catch(e) { s = ''; }
    var isVM = (s.indexOf('function %(lblfpo)s') === 0) && (s.length > 10000);
    if (isVM) {
      if (W.__origSrc === null) W.__origSrc = s;
      if (W.__useGuard) return W.__origSrc;
    }
    return s;
  };
  Function.prototype.toString = guard;
  try {
    Object.defineProperty(guard, 'toString', {
      value: function(){ return 'function toString() { [native code] }'; },
      writable: false, configurable: false
    });
  } catch(e) {}
})();
"""


def extract_inline_script(html):
    inlines = re.findall(
        r"<script(?![^>]*src)[^>]*>(.*?)</script>", html, re.S)
    best = None
    for t in inlines:
        if best is None or len(t) > len(best):
            best = t
    return best


def find_lf_name(src):
    for m in re.finditer(r"function (\w+)\s*\((\w+)\)\s*\{", src):
        body = src[m.end():m.end() + 2500]
        if "openArgs" in body:
            return m.group(1)
    return "Lf" if "function Lf(" in src else None


def patch_source(src, lf_name):
    notes = []
    pat_lf = re.compile(
        r"(function %s\s*\([^)]*\)\s*\{[^{]*try\{t\.push\(175\);)" % lf_name)
    m = pat_lf.search(src)
    if m:
        src = src[:m.end()] + "__capLf(%s);" % lf_name + src[m.end():]
        notes.append("Lf-cap")
    m_lk = re.search(r"function LK\s*\([^)]*\)\s*\{", src)
    if m_lk:
        src = src[:m_lk.end()] + "__lkLog(arguments);" + src[m_lk.end():]
        notes.append("LK-log")
    fetch_old = (r"(Z['n'][SC(tB.F)][SC(tB.X)+SC(tB.C)]"
                 r"||Z['n'][SC(tB.F)][SC(tB.e)])"
                 r"(Lb,LZ[SC(tB.Y)])")
    if fetch_old in src:
        src = src.replace(fetch_old, "__fetchShim(Lb,LZ[SC(tB.Y)])")
        notes.append("fetchShim")
    pat_b = re.compile(r"if\(Z\['n'\]\[SC\(tB\.G\)\]\[SC\(tB\.O\)\]\)")
    hits = pat_b.findall(src)
    if hits:
        src = pat_b.sub("if(true)", src)
        notes.append("forceB")
    return src, notes


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

BODY = {
    "filter": {}, "pageNumber": 1, "pageSize": 10, "keys": {"7": "263"},
    "order": 1, "activityIds": [], "frontCateIds": [], "frontBrandIds": [],
    "param": {
        "category": "%20", "cid": "263", "cmsPageId": "1cd71e2661000",
        "fromSearchUrl": "1", "order": "1", "originFrom": "h5",
        "platform": "h5", "purchaseType": "1", "scene": "qpol",
        "searchField": "%E7%83%AD%E5%8C%BA%E7%BB%84%E4%BB%B6",
        "stamp": "AA", "status": "0"
    },
    "sceneId": 0, "priceExp": True
}


def main():
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("v3 start %s\n" % time.strftime("%H:%M:%S"))

    # ===== 1. 新鲜挑战材料 =====
    session = requests.Session()
    session.headers.update(HEADERS)
    pylog("== 1. GET API 拿新鲜挑战页 ==")
    r = session.get(API, timeout=20)
    ct = r.headers.get("content-type", "")
    pylog("  status=%s len=%s ct=%s" % (r.status_code, len(r.text), ct))
    if "json" in ct:
        pylog("  未被挑战, 直接 JSON — 保存退出")
        with open("final_step3_v3_data.json", "w", encoding="utf-8") as f:
            f.write(r.text)
        return
    challenge_html = r.text
    acw_tc = None
    try:
        acw_tc = session.cookies.get("acw_tc")
    except Exception:
        pass
    if not acw_tc:
        m = re.search(r"acw_tc=([^;]+)", r.headers.get("Set-Cookie", ""))
        acw_tc = m.group(1) if m else None
    pylog("  acw_tc=%s" % acw_tc)

    inline_src = extract_inline_script(challenge_html)
    pylog("  inline: %d 字符" % len(inline_src))
    srcs = re.findall(r'<script[^>]*\ssrc="([^"]+)"', challenge_html)
    ext_path = srcs[-1]
    ext_url = "https://api.cdfsunrise.com" + ext_path
    lf_name = find_lf_name(inline_src)
    pylog("  lf_name=%s ext=%s" % (lf_name, ext_url))
    m_lbl = re.match(r"\s*\(\s*function (\w+)\s*\(\s*\)", inline_src)
    lblfpo_name = m_lbl.group(1) if m_lbl else "Lblfpo"
    pylog("  lblfpo_name=%s" % lblfpo_name)
    patched, notes = patch_source(inline_src, lf_name)
    pylog("  补丁: %s" % notes)
    if len(notes) < 4:
        pylog("[!] 补丁不全, 中止")
        return

    body_str = json.dumps(BODY, ensure_ascii=False, separators=(",", ":"))

    # page_load 用 HTML: ext src 换全 URL
    html2 = challenge_html.replace(
        'src="%s"' % ext_path, 'src="%s"' % ext_url)

    # ===== 2. 沙箱: page_load 原版 → 间谍捕获 → eval 补丁版 =====
    import iv8_rs
    calls = []
    post_result = {}

    def handler(url, method):
        calls.append({"url": url, "method": method})
        pylog("[handler] %s %s" % (method, url[:200]))
        if "md5__1803=" in url and method == "POST":
            pylog("  ★ requests 同Session POST 签名URL...")
            try:
                rr = session.post(url, data=body_str.encode("utf-8"))
                ct2 = rr.headers.get("content-type", "")
                pylog("  ★ status=%s len=%s ct=%s server=%s"
                      % (rr.status_code, len(rr.content), ct2,
                         rr.headers.get("server", "")))
                post_result.update({"status": rr.status_code, "ct": ct2,
                                     "len": len(rr.content), "body": rr.text})
                if rr.status_code == 200 and "json" in ct2:
                    try:
                        j = rr.json()
                        goods = j.get("goodsList") or []
                        pylog("  ★★ totalCount=%s, 本页商品数=%d"
                              % (j.get("totalCount"), len(goods)))
                        for i, g in enumerate(goods, 1):
                            pylog("  %2d. ¥%-8s %s"
                                  % (i, g.get("price", "?"),
                                     g.get("goodsName", "?")))
                        post_result["json"] = j
                    except Exception as e:
                        pylog("  json: %r" % e)
                else:
                    pylog("  head: %s" % rr.text[:160])
                return rr.status_code, rr.text
            except Exception as e:
                pylog("  真发异常: %r" % e)
                return 200, "{}"
        if "md5__1803=" in url:
            return 200, '{"isSuccess":true}'
        if url.rstrip("/") == API:
            return 200, challenge_html
        if url == ext_url:
            return 200, read("ext_solver.js")
        return None

    ctx = iv8_rs.JSContext()
    try:
        ctx.expose("__pylog", lambda m: pylog(str(m)))
        ctx.add_resource(ext_url, read("ext_solver.js"), status=200,
                         headers={"content-type": "application/javascript"})
        ctx.add_resource(API, challenge_html, status=200,
                         headers={"content-type": "text/html; charset=utf-8"})
        ctx.set_network_handler(handler)

        ctx.eval(r"""
window.__lfHook=null;window.__apiUrl=%(api)r;
window.__capLf=function(f){window.__lfHook=f;};
window.__lkCalls=[];
window.__lkLog=function(args){
  var a=[];
  for(var i=0;i<args.length;i++){
    var v=args[i];
    try{
      if(typeof v==='function')a.push('FN');
      else if(typeof v==='object'&&v!==null)a.push('OBJ');
      else a.push(String(v).slice(0,120));
    }catch(e){a.push('?');}
  }
  window.__lkCalls.push(a);
};
window.__fetchShim=function(u,i){return window.fetch(u,i);};
window.__useGuard=false;
""" % {"api": API})
        ctx.eval(SPY_GUARD_JS % {"lblfpo": lblfpo_name})

        # page_load 原版 (DOM+cookie 上下文, 间谍捕获 toString)
        pylog("== 2. page_load 原版挑战页 ==")
        sc = [("Set-Cookie",
               "acw_tc=%s; path=/; HttpOnly; Max-Age=1800" % acw_tc)]
        ctx.page_load_with_headers(html2, base_url=API, headers=sc)
        for _ in range(4):
            ctx.eval("__iv8__.eventLoop.drain()")
            ctx.eval("__iv8__.eventLoop.advance(1000)")
            ctx.eval("__iv8__.eventLoop.drain()")
        get_sig = ctx.eval("location.href")
        orig_len = ctx.eval("(window.__origSrc||'').length")
        pylog("  page_load done: 间谍原文=%s, href=%s..."
              % (orig_len, str(get_sig)[:120]))
        pylog("  cookie=%s" % ctx.eval("document.cookie")[:150])
        if not orig_len:
            pylog("[!] 间谍未捕获 — 中止")
            return

        # eval 补丁版 (guard 返回原文 → tp 自校验通过)
        pylog("== 3. eval 补丁版 (捕获 Lf) ==")
        ctx.eval("window.__useGuard=true;")
        ctx.eval(patched, name="inline_patched.js")
        for _ in range(4):
            ctx.eval("__iv8__.eventLoop.drain()")
            ctx.eval("__iv8__.eventLoop.advance(1000)")
            ctx.eval("__iv8__.eventLoop.drain()")
        st = ctx.eval("typeof window.__lfHook")
        pylog("  Lf 捕获: %s" % st)
        if st != "function":
            pylog("[!] 捕获失败 — 中止")
            return

        # ===== 4. GET 探路 (路径C签名, 预期 404=WAF放行) =====
        if isinstance(get_sig, str) and "md5__1803=" in get_sig:
            pylog("== 4. GET 探路: %s" % get_sig[:100])
            try:
                rg = session.get(get_sig, timeout=20)
                pylog("  GET status=%s len=%s ct=%s server=%s (404=WAF放行)"
                      % (rg.status_code, len(rg.content),
                         rg.headers.get("content-type", ""),
                         rg.headers.get("server", "")))
            except Exception as e:
                pylog("  GET 异常: %r" % e)

        # ===== 5. Lf(LZ POST) → LK 签名 → requests 真发 =====
        pylog("== 5. Lf(LZ POST) → POST 签名 ==")
        n0 = len(calls)
        ctx.eval(r"""
(function(){
  var Lf = window.__lfHook;
  var API = window.__apiUrl;
  var BODY = %(body_json)s;
  var LZ = {
    input: API,
    init: {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'usersystem': 'h5platform', 'miniapp': 'h5', 'appversion': '1.60.0',
        'clientnetwork': 'unknown', 'mobile': '', 'accesstoken': '',
        'device': '', 'deviceid': '', 'openid': '', 'alipayopenid': '',
        'unionid': ''
      },
      body: BODY,
      credentials: 'include'
    }
  };
  Lf(LZ).then(function(r){
    return r.text().then(function(t){
      window.__fr = JSON.stringify({status: r.status,
        ctype: r.headers.get('content-type'), head: t.slice(0, 300)});
    });
  }).catch(function(e){
    window.__fr = JSON.stringify({err: String(e)});
  });
})()
""" % {"body_json": json.dumps(body_str)})
        for _ in range(10):
            ctx.eval("__iv8__.eventLoop.drain()")
            ctx.eval("__iv8__.eventLoop.advance(1000)")
            ctx.eval("__iv8__.eventLoop.drain()")

        fr = ctx.eval("JSON.stringify(window.__fr||null)")
        pylog("  沙箱fetch: %s" % str(fr)[:300])
        lk = ctx.eval("JSON.stringify(window.__lkCalls||[])")
        pylog("  LK调用: %s" % str(lk)[:400])
        for c in calls[n0:]:
            mark = "★POST签名" if ("md5__1803=" in c["url"]
                                  and c["method"] == "POST") else ""
            pylog("  call: %s %s %s" % (c["method"], c["url"][:200], mark))

        # 汇总
        out = {"acw_tc": acw_tc, "get_sig": str(get_sig)[:500],
              "lk": json.loads(lk) if lk else [],
              "post": {k: v for k, v in post_result.items()
                       if k != "json"},
              "calls": calls}
        if "json" in post_result:
            out["totalCount"] = post_result["json"].get("totalCount")
            with open("final_step3_v3_data.json", "w", encoding="utf-8") as f:
                json.dump(post_result["json"], f, ensure_ascii=False,
                          indent=2)
            pylog("\n★★★★★ Step3 成功! totalCount=%s → final_step3_v3_data.json"
                  % out["totalCount"])
        with open("final_step3_v3_result.json", "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2, default=str)
    finally:
        ctx.close()
    pylog("v3 DONE")


if __name__ == "__main__":
    main()
