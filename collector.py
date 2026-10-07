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
import time
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

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT", "KDDI", "DOCOMO", "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "AT&T", "COMCAST", "XFINITY", "VERIZON", "TELUS", "ROGERS", "BELL CANADA",
    "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM", "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB",
    "KT", "SK BROADBAND", "LGU+", "LG POWERCOM", "KOREA TELECOM", "CHUNGHWA",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港", "AU": "澳大利亚",
}

def log(section, msg=""):
    print(f"[{section}] {msg}", flush=True)

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

def classify_network(host, org):
    if host.lower().startswith("public-vpn"):
        return "datacenter"
    org = (org or "").upper()
    if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
        return "datacenter"
    if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
        return "residential"
    if re.match(r"^vpn\d{5,}", host.lower()):
        return "residential"
    return "residential"

def check_one(node, session, check_base_url):
    target = f"{node['host']}:{node['port']}"
    url = f"{check_base_url}{target}"
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{target}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["residential"] = "unknown"
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
        out["residential"] = classify_network(out["host"], "")
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

def run_worker_checks(nodes):
    if not TARGET_ENDPOINT:
        log("CHECK", "No TARGET_ENDPOINT specified. Skipping worker deep probe.")
        for n in nodes:
            n["success"] = True
            n["status"] = "success"
            n["latency_ms"] = 0
            n["residential"] = classify_network(n["host"], "")
        return nodes

    session = requests.Session()
    session.headers.update({"User-Agent": GLOBAL_UA})
    
    # 自动登录支持 (针对 edgetunnel 带密码实例)
    if ADMIN_PASS:
        try:
            parsed = urlparse(TARGET_ENDPOINT)
            login_url = f"{parsed.scheme}://{parsed.netloc}/login"
            log("AUTH", f"Authenticating with target management endpoint: {login_url}")
            lr = session.post(login_url, data={"password": ADMIN_PASS}, timeout=15)
            log("AUTH", f"Auth response: HTTP {lr.status_code}")
        except Exception as e:
            log("AUTH", f"Auth error: {e}")

    log("CHECK", f"Submitting {len(nodes)} online endpoints to edge worker probe (concurrency={CONCURRENCY})...")
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session, TARGET_ENDPOINT) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

def build_nodes_text(available_nodes):
    lines = []
    # 按国家分组，住宅优先，延迟升序
    ordered = sorted(available_nodes, key=lambda n: (
        0 if n.get("residential") == "residential" else 1,
        n.get("latency_ms") is None,
        n.get("latency_ms") or 9999
    ))
    res_count = {}
    dc_count = {}
    for n in ordered:
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
        
        target = f"{n['host']}:{n['port']}"
        lines.append(f"{HOSTS_ENTRY}#{tag}$sstp://vpn:vpn@{target}")
    return "\n".join(lines) + "\n"

def main():
    rows, source = fetch_raw_nodes()
    raw_count = len(rows)
    tcp_nodes = filter_tcp_nodes(rows)
    log("FILTER", f"Raw: {raw_count} | TCP/SSTP Candidates: {len(tcp_nodes)}")

    # 本地前置预检
    online_nodes = pre_filter_nodes(tcp_nodes)
    
    # 边缘探活
    results = run_worker_checks(online_nodes)
    available = [r for r in results if r.get("success")]
    log("SUMMARY", f"Total online probes: {len(online_nodes)} | Verified Active: {len(available)}")

    os.makedirs(PUBLIC_DIR, exist_ok=True)

    # 1. public/data.json
    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
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

    # 2. public/nodes.txt
    nodes_txt = build_nodes_text(available)
    with open(os.path.join(PUBLIC_DIR, "nodes.txt"), "w", encoding="utf-8") as f:
        f.write(nodes_txt)

    # 3. public/index.html
    html_file = os.path.join(REPO_DIR, "web", "index.html")
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            html_content = f.read()
        with open(os.path.join(PUBLIC_DIR, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_content)

    log("OUTPUT", f"Generated public/data.json, public/nodes.txt ({len(available)} nodes), public/index.html")

if __name__ == "__main__":
    main()
