# 中免日上 H5 接口逆向 · 阿里云 WAF 签名分析

对中免日上 H5 商城（`h5.cdfsunrise.com`）受**阿里云 WAF JS 挑战**保护的接口
`POST https://api.cdfsunrise.com/restapi/search/list` 做签名机制逆向，
用 Python 稳定获取商品列表 / 详情 JSON。

> ⚠️ 仅用于授权范围内的安全研究与 JS 逆向学习，请勿高频请求或商用。

## 原理简述

目标接口的 URL 上带一个运行时生成的签名参数 `?md5__1803=<value>`，
由阿里云 WAF 下发的内联挑战脚本计算。几个关键特性决定了整个方案：

- **签名只在 URL**：签名请求与裸请求的 headers / body 完全一致。
- **一次性且绑定请求特征**：签名与当次请求的 URL / body / headers 绑定，
  换一个请求即失效，无法保存复用。
- **与挑战会话绑定**：必须用「新鲜挑战页 + 新 `acw_tc`」，
  且签名与挑战页加载处于同一 session。
- **脚本有自校验**：挑战脚本的源码文本参与内部字符串解码（哈希校验），
  因此**不能格式化、不能改源码**，否则脚本直接崩。

由此得到下面两条可行路线。

## 两条可行路线

| 路线 | 方式 | 状态 |
| --- | --- | --- |
| **A. 纯协议** | `requests` + `iv8_rs` 沙箱本地执行 WAF 挑战脚本 → 生成签名 → 直连接口 | ✅ 已跑通（`200` 真实商品 JSON） |
| **B. 浏览器被动收割** | `playwright` 驱动真实 Edge/Chrome，页面自己算签名，Python 只监听响应 | ✅ 稳定可用 |

补充：**商品详情接口 `POST /restapi/search/item/v3` 不在 WAF 强校验名单内**，
裸 `requests` 直接 POST 即返回真实 JSON，无需任何签名（见 `final_detail.py`）。
强校验只针对 `search/list` 等少数路径。

## 快速开始

环境要求：Windows + Python 3.13。

### 路线 B：浏览器被动收割

依赖：`requests` + `playwright` + 真实安装的 Edge 或 Chrome。

```powershell
pip install playwright requests
python -m playwright install msedge

python -X utf8 recycle/fetch_goods.py 1     # 列表页 → goods_p1.json
python -X utf8 fetch_detail.py <goodsId>    # 详情页 → detail_capture.json
```

### 路线 A：纯协议全链路

依赖：`requests` + **iv8_rs 沙箱**（`ming_iv8_rs`，纯 Python 进程内执行浏览器 JS
的 V8 运行时，未发布到 PyPI，需自行获取 wheel 后安装）。

```powershell
python -X utf8 final_step3_v3.py            # → final_step3_v3_result.json
```

### 商品详情：零依赖纯协议

`POST /restapi/search/item/v3` 不在 WAF 强校验名单内，裸 `requests` 直接可用：

```powershell
python -X utf8 final_detail.py <goodsId>    # → detail_item_v3.json
```

## 注意事项

- 抓取脚本**不要覆盖 User-Agent**——覆盖后与浏览器自生成的 `sec-ch-ua`
  不匹配，会陷入 WAF 无限挑战循环。
- 路线 B 中 Python 只做**被动**监听，不构造 / 重放任何请求。
- 挑战脚本（`waf-raw.js`）**禁止格式化**，会破坏其自校验文本。

## 免责声明

本项目所有分析均基于公开可访问的前端 JavaScript 与自身会话流量，
不含漏洞利用或绕过身份认证的尝试。请遵守目标站点的服务条款，
不要高频请求、不要用于商业用途，使用后果自行承担。
