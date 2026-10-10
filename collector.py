#!/usr/bin/env python3
"""
Edge Metric Sync - Telemetry & Latency Prober
"""

import base64
import csv
import io
import json
import os
import re
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)

TARGET_ENDPOINT = os.environ.get("TARGET_ENDPOINT", "")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
HOSTS_ENTRY = os.environ.get("HOSTS_ENTRY", "hyl-mold.ccwu.cc:443")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "16")))
PRE_FILTER_CONCURRENCY = max(1, int(os.environ.get("PRE_FILTER_CONCURRENCY", "30")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "60"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "30"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
GLOBAL_UA = "Mozilla/5.0 (NetProbe)"

# 保底阈值：可用节点少于此数时，不覆盖已发布的 nodes.txt（避免订阅被清空）
MIN_NODES = max(1, int(os.environ.get("MIN_NODES", "10")))
# 已发布产物地址（用于取回上一份可用 nodes.txt 做保底回退）
PAGES_BASE = os.environ.get("PAGES_BASE", "https://longgegege21.github.io/edge-metric-sync")

# 优选入口 API：按运营商线路返回 CF 原生优选 IP（格式 IP:port#备注）。
# 留空则退回固定的 HOSTS_ENTRY。电信=/ct，联通=/cu，移动=/cmcc
OPTIMAL_API = os.environ.get("OPTIMAL_API", "")

# IP 情报接口（判定住宅/机房），ip-api.com 免费批量接口
IPAPI_BATCH = os.environ.get("IPAPI_BATCH", "http://ip-api.com/batch")
IPAPI_FIELDS = "status,query,hosting,proxy,isp,org,as,countryCode"

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港", "AU": "澳大利亚",
}

def log(section, msg=""):
    print(f"[{section}] {msg}", flush=True)

# ---------------------------------------------------------------------------
# 线程本地 Session
# 修复：原实现把单个 requests.Session 交给 16 个线程并发复用。
# requests.Session 并非线程安全，并发下会出现连接池串扰 / Cookie 错乱 / 随机失败。
# ---------------------------------------------------------------------------
_thread_local = threading.local()
_base_cookies = None

def _do_login():
    """主线程登录一次，取回认证 Cookie，供各工作线程复用。"""
    global _base_cookies
    if not ADMIN_PASS or not TARGET_ENDPOINT:
        return
    try:
        parsed = urlparse(TARGET_ENDPOINT)
        login_url = f"{parsed.scheme}://{parsed.netloc}/login"
        log("AUTH", f"Authenticating with target management endpoint: {login_url}")
        s = requests.Session()
        s.headers.update({"User-Agent": GLOBAL_UA})
        lr = s.post(login_url, data={"password": ADMIN_PASS}, timeout=15)
        log("AUTH", f"Auth response: HTTP {lr.status_code}")
        _base_cookies = s.cookies
    except Exception as e:
        log("AUTH", f"Auth error: {e}")

def get_session():
    """每个线程各自惰性创建一个 Session，并复用登录 Cookie。"""
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": GLOBAL_UA})
        if _base_cookies:
            s.cookies.update(_base_cookies)
        _thread_local.session = s
    return s

def fetch_raw_nodes():
    log("FETCH", f"Fetching source: {VPNGATE_API}")
    try:
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": GLOBAL_UA})
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("FETCH", f"Primary API returned {len(rows)} nodes")
            return rows, "vpngate.net"
    except Exception as exc:
        log("FETCH", f"Primary API failed: {exc}, switching to mirror")

    try:
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": GLOBAL_UA})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("FETCH", f"Mirror returned {len(rows)} nodes")
            return rows, "github-mirror"
    except Exception as exc:
        log("FETCH", f"Mirror failed: {exc}")

    sys.exit("[FATAL] All data sources failed.")

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        return []
    header = lines[header_idx].lstrip("#").split(",")
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "b64": idx.get("openvpn_configdata_base64", len(header) - 1)
    }
    rows = []
    for ln in lines[header_idx + 1:]:
        try:
            fields = next(csv.reader(io.StringIO(ln)))
            if len(fields) < 7: continue
            host = fields[pos["hostname"]].strip()
            ip = fields[pos["ip"]].strip()
            if not host or not ip: continue
            rows.append({
                "host": host, "ip": ip,
                "country_long": fields[pos["countrylong"]].strip(),
                "country_short": fields[pos["countryshort"]].strip(),
                "config_b64": fields[pos["b64"]].strip()
            })
        except Exception:
            continue
    return rows

def parse_mirror_json(data):
    servers = data if isinstance(data, list) else data.get("servers", [])
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        rows.append({
            "host": host, "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip()
        })
    return rows

_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def filter_tcp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                pass
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host, "port": port, "ip": r["ip"],
            "country": r["country_long"], "country_code": r["country_short"]
        })
    seen = set()
    uniq = []
    for n in nodes:
        k = (n["host"].lower(), n["port"])
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    return uniq

def tcp_pre_check(node):
    """Actions 本地预检: 1 秒超时测试端口是否开放，剔除已关机节点"""
    try:
        with socket.create_connection((node["ip"], node["port"]), timeout=1.0):
            return node, True
    except Exception:
        return node, False

def pre_filter_nodes(nodes):
    log("PRE_FILTER", f"Running TCP pre-filter on {len(nodes)} candidate endpoints (concurrency={PRE_FILTER_CONCURRENCY})...")
    alive = []
    with ThreadPoolExecutor(max_workers=PRE_FILTER_CONCURRENCY) as pool:
        futures = [pool.submit(tcp_pre_check, n) for n in nodes]
        for fut in as_completed(futures):
            n, ok = fut.result()
            if ok:
                alive.append(n)
    log("PRE_FILTER", f"TCP pre-filter passed: {len(alive)}/{len(nodes)} endpoints online")
    return alive

def enrich_ip_meta(nodes):
    """批量查询节点 IP 归属（ip-api.com/batch），作为住宅/机房判定依据。

    返回 {ip: {status, hosting, proxy, isp, org, as, countryCode, query}}。
    修复：原 classify_network 的 org 关键词表从未被喂入数据，判定实际退化为
    「public-vpn-* → 机房，其余一律住宅」，导致大量 VPS 中继被误标为住宅。
    """
    ips = sorted({n["ip"] for n in nodes if n.get("ip")})
    meta = {}
    if not ips:
        return meta
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            resp = requests.post(
                f"{IPAPI_BATCH}?fields={IPAPI_FIELDS}",
                json=[{"query": ip} for ip in chunk],
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": GLOBAL_UA},
            )
            resp.raise_for_status()
            for item in resp.json():
                q = item.get("query")
                if q:
                    meta[q] = item
        except Exception as exc:
            log("ENRICH", f"ip-api batch failed (chunk {i // 100}): {exc}")
    log("ENRICH", f"Enriched {len(meta)}/{len(ips)} node IPs via ip-api")
    return meta

def classify_network(host, meta=None):
    """住宅/机房判定：优先用 IP 情报(ip-api 的 hosting 标记)，回退到 host 规则。"""
    # VPN Gate 项目自有服务器（public-vpn-*，ISP=SoftEther）一律视为机房。
    # 不能仅凭 ip-api 的 hosting 标记：SoftEther 的 ASN 会被判为 non-hosting。
    if host.lower().startswith("public-vpn"):
        return "datacenter"
    if isinstance(meta, dict) and meta.get("status") == "success":
        if meta.get("hosting") is True:
            return "datacenter"
        org = f"{meta.get('isp', '')} {meta.get('org', '')} {meta.get('as', '')}".upper()
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        return "residential"
    # 回退：无 IP 情报时按 host 命名规则
    return "residential"

def check_one(node, check_base_url, ip_meta):
    session = get_session()
    target = f"{node['host']}:{node['port']}"
    url = f"{check_base_url}{target}"
    src_ip = node.get("ip")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{target}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["residential"] = classify_network(out["host"], ip_meta.get(src_ip))
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT)
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["ip"] = j.get("ip") or out.get("ip")
        out["loc"] = j.get("loc") or out.get("country_code")
        out["error"] = None if ok else (j.get("error") or "check failed")
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

def run_worker_checks(nodes, ip_meta):
    if not TARGET_ENDPOINT:
        log("CHECK", "No TARGET_ENDPOINT specified. Skipping worker deep probe.")
        for n in nodes:
            n["success"] = True
            n["status"] = "success"
            n["latency_ms"] = 0
            n["residential"] = classify_network(n["host"], ip_meta.get(n.get("ip")))
        return nodes

    _do_login()
    log("CHECK", f"Submitting {len(nodes)} online endpoints to edge worker probe (concurrency={CONCURRENCY})...")
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, TARGET_ENDPOINT, ip_meta) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def _parse_optimal_text(text):
    """把优选 API 返回文本解析成 ['IP:port', ...]。

    严格只接受 IPv4[:port]（可带 #备注）。宁可返回空（回退固定入口），
    也绝不把 HTML 错误页/垃圾内容当成入口——否则会污染 nodes.txt
    （实测：源返回 HTML 时曾解析出 413 条垃圾）。
    """
    if not text or "<" in text or ">" in text:   # HTML / 错误页，直接拒绝
        return []
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        addr = line.split("#")[0].strip()
        if not addr:
            continue
        if ":" in addr:
            host, _, port = addr.rpartition(":")
        else:
            host, port = addr, "443"
        host = host.strip()
        if not _IPV4_RE.match(host):
            continue
        if any(int(o) > 255 for o in host.split(".")):
            continue
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            continue
        e = f"{host}:{port}"
        if e not in entries:
            entries.append(e)
    if len(entries) > 50:   # 数量离谱，判为异常内容
        return []
    return entries

def fetch_optimal_entries():
    """从优选 API 拉取入口列表（IP:port）。

    OPTIMAL_API 支持逗号分隔多个源，按顺序尝试，第一个返回非空的即采用；
    全部失败则返回 []，调用方回退到固定的 HOSTS_ENTRY（流水线不会因此中断）。
    优选只优化「客户端→CF 入口」这一段，不改变 CF→SSTP 那段。
    """
    sources = [s.strip() for s in OPTIMAL_API.split(",") if s.strip()]
    if not sources:
        return []
    for src in sources:
        try:
            r = requests.get(src, timeout=HTTP_TIMEOUT, headers={"User-Agent": GLOBAL_UA})
            r.raise_for_status()
            entries = _parse_optimal_text(r.text)
            if entries:
                log("OPTIMAL", f"Fetched {len(entries)} optimal entries from {src}")
                return entries
            log("OPTIMAL", f"{src} returned no usable entries; trying next source")
        except Exception as exc:
            log("OPTIMAL", f"Source failed ({src}): {exc}; trying next")
    log("OPTIMAL", "All optimal sources failed; falling back to HOSTS_ENTRY")
    return []

def build_nodes_text(available_nodes, entries=None):
    lines = []
    # 按国家分组，住宅优先，延迟升序
    ordered = sorted(available_nodes, key=lambda n: (
        0 if n.get("residential") == "residential" else 1,
        n.get("latency_ms") is None,
        n.get("latency_ms") or 9999
    ))
    res_count = {}
    dc_count = {}
    entries = entries or []
    for idx, n in enumerate(ordered):
        cc = (n.get("country_code") or "XX").upper()
        zh = COUNTRY_ZH.get(cc, cc)
        is_res = (n.get("residential") == "residential")
        if is_res:
            res_count[cc] = res_count.get(cc, 0) + 1
            seq = res_count[cc]
            tag = f"{zh}-住宅-{seq:02d}"
        else:
            dc_count[cc] = dc_count.get(cc, 0) + 1
            seq = dc_count[cc]
            tag = f"{zh}-机房-{seq:02d}"

        # 入口：有优选列表则轮换使用（前几个节点优先拿到最优入口），否则退回固定 HOSTS_ENTRY
        entry = entries[idx % len(entries)] if entries else HOSTS_ENTRY
        target = f"{n['host']}:{n['port']}"
        lines.append(f"{entry}#{tag}$sstp://vpn:vpn@{target}")
    return "\n".join(lines) + "\n"

def fetch_last_good_nodes():
    """取回当前已发布的 nodes.txt，作为保底回退内容。"""
    try:
        r = requests.get(f"{PAGES_BASE}/nodes.txt", timeout=HTTP_TIMEOUT, headers={"User-Agent": GLOBAL_UA})
        if r.status_code == 200 and r.text.strip():
            return r.text
    except Exception as exc:
        log("GUARD", f"Could not fetch last-good nodes.txt: {exc}")
    return None

def main():
    rows, source = fetch_raw_nodes()
    raw_count = len(rows)
    tcp_nodes = filter_tcp_nodes(rows)
    log("FILTER", f"Raw: {raw_count} | TCP/SSTP Candidates: {len(tcp_nodes)}")

    # 本地前置预检
    online_nodes = pre_filter_nodes(tcp_nodes)

    # IP 情报富化（住宅/机房判定依据）
    ip_meta = enrich_ip_meta(online_nodes)

    # 边缘探活
    results = run_worker_checks(online_nodes, ip_meta)
    available = [r for r in results if r.get("success")]
    log("SUMMARY", f"Total online probes: {len(online_nodes)} | Verified Active: {len(available)}")

    os.makedirs(PUBLIC_DIR, exist_ok=True)

    # 保底：可用节点过少时，回退到上一份已发布 nodes.txt，避免把订阅清空
    degraded = len(available) < MIN_NODES
    fallback_text = None
    if degraded:
        log("GUARD", f"Only {len(available)} active nodes (< MIN_NODES={MIN_NODES}).")
        fallback_text = fetch_last_good_nodes()
        if fallback_text:
            log("GUARD", "Refusing to overwrite subscription; republishing last-good nodes.txt.")
        else:
            log("GUARD", "No last-good snapshot available; publishing current result as-is (first run?).")

    # 优选入口（电信/联通/移动由 OPTIMAL_API 决定；为空则用固定 HOSTS_ENTRY）
    entries = fetch_optimal_entries()

    # 1. public/data.json
    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "degraded": degraded,
        "entries": entries,
        "stats": {
            "raw_nodes": raw_count,
            "tcp_candidates": len(tcp_nodes),
            "pre_online": len(online_nodes),
            "verified_active": len(available)
        },
        "nodes": available
    }
    with open(os.path.join(PUBLIC_DIR, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # 2. public/nodes.txt（保底时回退旧内容；顶部带时间标记）
    # 时间标记用注释行：edgetunnel 对不匹配 "地址[:端口][#备注]" 的行会 return null，
    # 随后被 .filter(item => item !== null) 过滤掉，因此注释行安全。
    # 但注释行内绝不能出现逗号——否则会被 isCSV = lines[0].includes(',') 误判为 CSV，整段按 CSV 解析。
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    res_n = sum(1 for n in available if n.get("residential") == "residential")
    dc_n = len(available) - res_n
    entry_desc = f"{len(entries)} optimal entries" if entries else HOSTS_ENTRY
    header_line = f"# updated {stamp} | {len(available)} nodes | {res_n} residential / {dc_n} datacenter | entry: {entry_desc}"
    nodes_content = fallback_text if (degraded and fallback_text) else header_line + "\n" + build_nodes_text(available, entries)
    with open(os.path.join(PUBLIC_DIR, "nodes.txt"), "w", encoding="utf-8") as f:
        f.write(nodes_content)

    # 3. public/index.html
    html_file = os.path.join(REPO_DIR, "web", "index.html")
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            html_content = f.read()
        with open(os.path.join(PUBLIC_DIR, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)

    log("OUTPUT", f"Generated public/data.json, public/nodes.txt ({len(available)} nodes, degraded={degraded}), public/index.html")

if __name__ == "__main__":
    main()
