#!/usr/bin/env python3
"""
VirusTotal bulk IP checker (free Public API).

- Looks up every IP with the free VirusTotal API v3 (4 req/min, 500/day).
- Keeps the IPs flagged by at least N vendors (default 1, malicious or suspicious).
- Captures a cropped proof screenshot for each flagged IP:
    * real VirusTotal detection page (via Playwright + Edge), or
    * fallback evidence card rendered from the API data.
- Writes a formatted Excel report (screenshots embedded), an HTML report,
  a plain list of malicious IPs, and the raw API JSON.

Usage:
    python vt_checker.py -i ips.txt
    python vt_checker.py 8.8.8.8 1.2.3.4 --screenshot card
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path

import requests
from openpyxl import Workbook
from openpyxl.drawing.image import Image as XLImage
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

BASE_DIR = Path(__file__).resolve().parent
VT_API = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_GUI = "https://www.virustotal.com/gui/ip-address/{ip}/detection"
FREE_TIER_INTERVAL = 15.5  # seconds between calls -> < 4 requests/minute


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


def load_ips(file_path: str | None, cli_ips: list[str]) -> list[str]:
    """Extract unique IPs, in order, from any text (plain lists, CSV / SIEM exports, logs)."""
    text = " ".join(cli_ips)
    if file_path:
        body = Path(file_path).read_text(encoding="utf-8-sig")
        text += "\n" + re.sub(r"(?m)^\s*#.*", "", body)  # allow comment lines
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

    seen, ips = set(), []
    for m in IPV4_RE.findall(text) + IPV6_RE.findall(text):
        try:
            ip = str(ipaddress.ip_address(m))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def load_internal_ranges(path: Path) -> list:
    """Extra networks to treat as internal (e.g. your organisation's own public ranges)."""
    nets = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    print(f"  ignoring bad range in {path.name}: {line}")
    return nets


def is_internal(ip: str, extra_nets: list) -> bool:
    addr = ipaddress.ip_address(ip)
    return not addr.is_global or any(addr in n for n in extra_nets)


def load_api_keys(cli_keys: list[str] | None) -> list[str]:
    """Keys from --api-key (repeatable), VT_API_KEY (comma separated) and vt_api_key.txt (one per line)."""
    keys = [k.strip() for k in (cli_keys or [])]
    keys += [k.strip() for k in os.environ.get("VT_API_KEY", "").split(",")]
    key_file = BASE_DIR / "vt_api_key.txt"
    if key_file.exists():
        for line in key_file.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("PASTE"):
                keys.append(line)
    keys = list(dict.fromkeys(k for k in keys if k))  # dedupe, keep order
    if not keys:
        sys.exit(
            "No VirusTotal API key found.\n"
            "Get a free one at https://www.virustotal.com/gui/my-apikey, then either:\n"
            "  - put it in vt_api_key.txt next to this script (one key per line), or\n"
            "  - set VT_API_KEY (comma separated for several), or\n"
            "  - pass --api-key KEY (repeatable)"
        )
    return keys


# --------------------------------------------------------------------------- #
# VirusTotal API
# --------------------------------------------------------------------------- #
class ApiKey:
    def __init__(self, key: str, label: str):
        self.key, self.label = key, label
        self.next_ok = 0.0   # monotonic time when this key may be used again
        self.strikes = 0     # consecutive 429s; 3 in a row = daily quota gone
        self.used = 0


class VTClient:
    """Rotates over several API keys, each paced to the free-tier rate on its own."""

    def __init__(self, api_keys: list[str], interval: float, cache_dir: Path, max_cache_age_h: float):
        self.session = requests.Session()
        self.session.headers.update({"accept": "application/json"})
        self.keys = [ApiKey(k, f"key#{i} (...{k[-4:]})") for i, k in enumerate(api_keys, start=1)]
        self.retired: list[tuple[ApiKey, str]] = []
        self.interval = interval
        self.cache_dir = cache_dir
        self.max_cache_age = max_cache_age_h * 3600
        cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, ip: str) -> Path:
        return self.cache_dir / (ip.replace(":", "_") + ".json")

    def cached(self, ip: str) -> dict | None:
        p = self._cache_path(ip)
        if p.exists() and time.time() - p.stat().st_mtime < self.max_cache_age:
            return json.loads(p.read_text(encoding="utf-8"))
        return None

    def _retire(self, k: ApiKey, reason: str):
        self.keys.remove(k)
        self.retired.append((k, reason))
        print(f"    {k.label} removed from rotation: {reason} ({len(self.keys)} key(s) left)")

    def _take_key(self) -> ApiKey | None:
        """Wait for the soonest-available key and reserve its next slot."""
        if not self.keys:
            return None
        k = min(self.keys, key=lambda x: x.next_ok)
        wait = k.next_ok - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        k.next_ok = time.monotonic() + self.interval
        return k

    def lookup(self, ip: str) -> tuple[int, dict]:
        """Return (http_status, json). Uses cache; rotates keys; retries on rate limiting."""
        cached = self.cached(ip)
        if cached is not None:
            return 200, cached

        net_errors = 0
        for _ in range(12):
            k = self._take_key()
            if k is None:
                break
            try:
                r = self.session.get(VT_API.format(ip=ip), headers={"x-apikey": k.key}, timeout=30)
            except requests.RequestException as e:
                net_errors += 1
                if net_errors >= 3:
                    return 0, {"error": {"code": "NetworkError", "message": str(e)}}
                time.sleep(10)
                continue

            if r.status_code == 429:
                k.strikes += 1
                if k.strikes >= 3:
                    self._retire(k, "quota exhausted (daily/monthly limit reached)")
                else:
                    k.next_ok = time.monotonic() + 60
                    print(f"    {k.label} rate limited, cooling down 60s")
                continue
            if r.status_code in (401, 403):
                self._retire(k, f"rejected by VirusTotal (HTTP {r.status_code}) - check the key")
                continue

            k.strikes, k.used = 0, k.used + 1
            try:
                body = r.json()
            except ValueError:
                body = {"error": {"code": "BadResponse", "message": r.text[:200]}}
            if r.status_code == 200:
                self._cache_path(ip).write_text(json.dumps(body), encoding="utf-8")
            return r.status_code, body
        return 429, {"error": {"code": "QuotaExceededError",
                               "message": "All API keys rate limited or out of quota"}}


def fmt_ts(ts: int | None) -> str:
    if not ts:
        return ""
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_record(ip: str, status: int, body: dict, min_detections: int) -> dict:
    rec = {
        "ip": ip, "status": "", "malicious": 0, "suspicious": 0, "harmless": 0,
        "undetected": 0, "total": 0, "flagged_by": [], "country": "", "as_owner": "",
        "asn": "", "network": "", "reputation": "", "last_analysis": "",
        "vt_link": VT_GUI.format(ip=ip), "note": "", "screenshot": "", "screenshot_kind": "",
    }
    if status == 404:
        rec["status"], rec["note"] = "Not in VT", "VirusTotal has no record of this IP"
        return rec
    if status != 200:
        err = body.get("error", {})
        rec["status"] = "Error"
        rec["note"] = f"{err.get('code', status)}: {err.get('message', '')}"[:300]
        return rec

    a = body.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    results = a.get("last_analysis_results", {})
    # Only explicit "malicious" verdicts count; "suspicious" is ignored.
    flagged = sorted(
        ((r.get("engine_name") or name, r.get("category"), r.get("result") or r.get("category"))
         for name, r in results.items() if r.get("category") == "malicious"),
        key=lambda f: f[0].lower(),
    )

    rec.update(
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total=sum(v for v in stats.values() if isinstance(v, int)),
        flagged_by=flagged,
        country=a.get("country", ""),
        as_owner=a.get("as_owner", ""),
        asn=a.get("asn", ""),
        network=a.get("network", ""),
        reputation=a.get("reputation", ""),
        last_analysis=fmt_ts(a.get("last_analysis_date")),
    )
    if len(flagged) >= min_detections:
        rec["status"] = "MALICIOUS"
    elif rec["suspicious"]:
        rec["status"], rec["note"] = "Clean", f"{rec['suspicious']} suspicious verdict(s) only - not listed"
    else:
        rec["status"] = "Clean"
    return rec


# --------------------------------------------------------------------------- #
# Screenshots
# --------------------------------------------------------------------------- #
CARD_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#fff;font-family:Segoe UI,Arial,sans-serif}}
#card{{width:640px;padding:18px 22px;border:2px solid #d32f2f;border-radius:10px;box-sizing:border-box}}
.hdr{{display:flex;justify-content:space-between;align-items:center}}
.ip{{font-size:22px;font-weight:700;color:#111}}
.badge{{background:#d32f2f;color:#fff;font-weight:700;border-radius:20px;padding:6px 14px;font-size:18px}}
.sub{{color:#555;font-size:12px;margin:4px 0 12px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th{{text-align:left;background:#f3f3f3;padding:5px 8px;border-bottom:1px solid #ddd}}
td{{padding:5px 8px;border-bottom:1px solid #eee}}
.mal{{color:#d32f2f;font-weight:600}} .sus{{color:#e08a00;font-weight:600}}
.meta{{font-size:12px;color:#333;margin-top:12px;line-height:1.6}}
.src{{font-size:11px;color:#777;margin-top:8px;word-break:break-all}}
</style></head><body><div id="card">
<div class="hdr"><div class="ip">{ip}</div><div class="badge">{det} / {total}</div></div>
<div class="sub">{det} of {total} security vendors flagged this IP address as malicious on VirusTotal</div>
<table><tr><th>Security vendor</th><th>Category</th><th>Verdict</th></tr>{rows}</table>
<div class="meta"><b>AS owner:</b> {as_owner} (AS{asn}) &nbsp; <b>Country:</b> {country}
&nbsp; <b>Network:</b> {network}<br><b>Last VT analysis:</b> {last} &nbsp; <b>Community reputation:</b> {rep}</div>
<div class="src">Source: VirusTotal API v3, retrieved {retrieved} &middot; {link}</div>
</div></body></html>"""


class Screenshotter:
    def __init__(self, out_dir: Path, headless: bool, channel: str, vt_wait: int, crop_height: int):
        from playwright.sync_api import sync_playwright

        self.out_dir = out_dir
        self.vt_wait = vt_wait * 1000
        self.crop_height = crop_height
        self._pw = sync_playwright().start()
        profile = BASE_DIR / ".browser_profile"
        launch = dict(user_data_dir=str(profile), headless=headless,
                      viewport={"width": 1400, "height": 1200}, locale="en-US")
        try:
            self.ctx = self._pw.chromium.launch_persistent_context(channel=channel or None, **launch)
        except Exception as e:
            print(f"  could not start '{channel}' browser ({e.__class__.__name__}); "
                  "trying Playwright's bundled Chromium")
            self.ctx = self._pw.chromium.launch_persistent_context(**launch)
        self.page = self.ctx.pages[0] if self.ctx.pages else self.ctx.new_page()

    def close(self):
        try:
            self.ctx.close()
        finally:
            self._pw.stop()

    def vt_page(self, ip: str, path: Path) -> bool:
        """Screenshot the top of the real VT detection page. False if blocked/unavailable."""
        page = self.page
        try:
            page.goto(VT_GUI.format(ip=ip), wait_until="domcontentloaded", timeout=45000)
            # Playwright text locators pierce VT's shadow DOM.
            page.get_by_text(re.compile(r"security vendors? flagged", re.I)).first.wait_for(
                timeout=self.vt_wait)
            page.wait_for_timeout(2000)  # let the vendor list render
            vp = page.viewport_size or {"width": 1400, "height": 1200}
            page.screenshot(path=str(path), clip={"x": 0, "y": 0, "width": vp["width"],
                                                  "height": min(self.crop_height, vp["height"])})
            return True
        except Exception:
            return False

    def card(self, rec: dict, path: Path) -> None:
        rows = "".join(
            f'<tr><td>{html.escape(eng)}</td>'
            f'<td class="mal">{html.escape(cat)}</td>'
            f"<td>{html.escape(str(res))}</td></tr>"
            for eng, cat, res in rec["flagged_by"]
        )
        doc = CARD_TEMPLATE.format(
            ip=html.escape(rec["ip"]), det=len(rec["flagged_by"]), total=rec["total"], rows=rows,
            as_owner=html.escape(str(rec["as_owner"] or "n/a")), asn=html.escape(str(rec["asn"] or "?")),
            country=html.escape(rec["country"] or "n/a"), network=html.escape(rec["network"] or "n/a"),
            last=html.escape(rec["last_analysis"] or "n/a"), rep=html.escape("n/a" if rec["reputation"] == "" else str(rec["reputation"])),
            retrieved=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            link=html.escape(rec["vt_link"]),
        )
        self.page.set_content(doc)
        self.page.locator("#card").screenshot(path=str(path))


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
HEADER_FILL = PatternFill("solid", fgColor="1F3864")
HEADER_FONT = Font(bold=True, color="FFFFFF")
RED_FILL = PatternFill("solid", fgColor="FDE2E2")
GREEN_FILL = PatternFill("solid", fgColor="E3F4E1")
GREY_FILL = PatternFill("solid", fgColor="EEEEEE")
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP_TOP = Alignment(wrap_text=True, vertical="top")


def _header(ws, headers, widths):
    ws.append(headers)
    for i, (h, w) in enumerate(zip(headers, widths), start=1):
        c = ws.cell(row=1, column=i)
        c.fill, c.font, c.border = HEADER_FILL, HEADER_FONT, BORDER
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.row_dimensions[1].height = 28
    ws.freeze_panes = "B2"


def flagged_text(rec: dict) -> str:
    return "\n".join(f"{e} - {r}" for e, _, r in rec["flagged_by"])


def write_excel(path: Path, records: list[dict], run_info: dict, img_width: int):
    wb = Workbook()

    # Sheet 1: malicious IPs with proof
    ws = wb.active
    ws.title = "Malicious IPs"
    headers = ["#", "IP Address", "Malicious Detections", "Flagged Malicious By (vendor - verdict)",
               "Country", "AS Owner (ASN)", "Last VT Analysis", "VirusTotal Link", "Proof Screenshot"]
    img_col_width = img_width / 7 + 2
    _header(ws, headers, [5, 18, 13, 42, 9, 28, 20, 18, img_col_width])

    bad = [r for r in records if r["status"] == "MALICIOUS"]
    for n, rec in enumerate(bad, start=1):
        row = n + 1
        ws.append([
            n, rec["ip"], f'{len(rec["flagged_by"])}/{rec["total"]}',
            flagged_text(rec), rec["country"], f'{rec["as_owner"]} (AS{rec["asn"]})' if rec["asn"] else "",
            rec["last_analysis"], "Open in VirusTotal", "",
        ])
        for col in range(1, len(headers) + 1):
            c = ws.cell(row=row, column=col)
            c.alignment, c.border = WRAP_TOP, BORDER
        ws.cell(row=row, column=2).font = Font(bold=True, color="C00000")
        link = ws.cell(row=row, column=8)
        link.hyperlink, link.font = rec["vt_link"], Font(color="0563C1", underline="single")

        text_height = 15 * max(1, len(rec["flagged_by"]))
        img_height = 0
        if rec["screenshot"] and Path(rec["screenshot"]).exists():
            img = XLImage(rec["screenshot"])
            scale = img_width / img.width
            img.width, img.height = img_width, int(img.height * scale)
            img_height = img.height * 0.75 + 6  # px -> points
            ws.add_image(img, f"I{row}")
        ws.row_dimensions[row].height = min(409, max(text_height, img_height, 20))

    if not bad:
        ws.append(["", "No IP was flagged as malicious by any vendor."])
    ws.auto_filter.ref = f"A1:H{max(2, len(bad) + 1)}"

    # Sheet 2: every IP checked
    ws2 = wb.create_sheet("All Results")
    _header(ws2, ["IP Address", "Status", "Malicious", "Suspicious", "Harmless", "Undetected",
                  "Total Engines", "Country", "AS Owner", "Note"],
            [18, 13, 11, 11, 11, 11, 13, 9, 30, 50])
    for rec in records:
        ws2.append([rec["ip"], rec["status"], rec["malicious"], rec["suspicious"], rec["harmless"],
                    rec["undetected"], rec["total"], rec["country"], rec["as_owner"], rec["note"]])
        r = ws2.max_row
        fill = {"MALICIOUS": RED_FILL, "Clean": GREEN_FILL}.get(rec["status"], GREY_FILL)
        if rec["status"] == "Clean" and rec["suspicious"]:
            fill = PatternFill("solid", fgColor="FFF2CC")
        for col in range(1, 11):
            c = ws2.cell(row=r, column=col)
            c.border = BORDER
            if col == 2:
                c.fill = fill
                c.font = Font(bold=rec["status"] == "MALICIOUS")
    ws2.auto_filter.ref = f"A1:J{max(2, ws2.max_row)}"

    # Sheet 3: run info
    ws3 = wb.create_sheet("Run Info")
    ws3.column_dimensions["A"].width, ws3.column_dimensions["B"].width = 28, 70
    for k, v in run_info.items():
        ws3.append([k, str(v)])
        ws3.cell(row=ws3.max_row, column=1).font = Font(bold=True)

    wb.save(path)


def write_html(path: Path, records: list[dict], run_info: dict):
    bad = [r for r in records if r["status"] == "MALICIOUS"]
    rows = []
    for n, rec in enumerate(bad, start=1):
        shot = ""
        if rec["screenshot"]:
            rel = Path(rec["screenshot"]).relative_to(path.parent).as_posix()
            shot = f'<a href="{rel}" target="_blank"><img src="{rel}"></a><div class="k">{rec["screenshot_kind"]}</div>'
        vendors = "<br>".join(html.escape(l) for l in flagged_text(rec).split("\n"))
        rows.append(
            f"<tr><td>{n}</td><td class='ip'>{rec['ip']}</td>"
            f"<td><b>{len(rec['flagged_by'])}/{rec['total']}</b></td><td>{vendors}</td>"
            f"<td>{html.escape(rec['country'])}<br>{html.escape(str(rec['as_owner']))}</td>"
            f"<td>{rec['last_analysis']}<br><a href='{rec['vt_link']}' target='_blank'>VirusTotal</a></td>"
            f"<td>{shot}</td></tr>")
    info = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>"
                   for k, v in run_info.items())
    path.write_text(f"""<!doctype html><html><head><meta charset="utf-8">
<title>{html.escape(path.stem)}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}}
h1{{margin:0 0 4px}} table{{border-collapse:collapse;width:100%;margin-top:14px}}
th,td{{border:1px solid #ccc;padding:6px 8px;vertical-align:top;font-size:13px;text-align:left}}
th{{background:#1f3864;color:#fff}} .ip{{font-weight:700;color:#c00000}}
img{{max-width:460px;border:1px solid #aaa}} .k{{font-size:11px;color:#777}}
.info th{{background:#f0f0f0;color:#222;width:220px}}
</style></head><body>
<h1>IP Blocklist - VirusTotal malicious verdicts</h1>
<table class="info">{info}</table>
<h2>Malicious IPs ({len(bad)})</h2>
<table><tr><th>#</th><th>IP</th><th>Malicious</th><th>Flagged malicious by</th><th>Country / AS</th>
<th>Last analysis</th><th>Proof</th></tr>{''.join(rows) or '<tr><td colspan=7>None flagged.</td></tr>'}</table>
</body></html>""", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(description="Bulk-check IPs on VirusTotal (free API) and build a malicious-IP blocklist.")
    p.add_argument("ips", nargs="*", help="IP addresses (optional if -i is used)")
    p.add_argument("-i", "--input", help="any text/CSV file containing IPs (plain list, SIEM export, logs)")
    p.add_argument("-o", "--output", default=str(BASE_DIR / "output"), help="output folder (default: ./output)")
    p.add_argument("--api-key", action="append",
                   help="VirusTotal API key; repeat for several (also VT_API_KEY env / vt_api_key.txt)")
    p.add_argument("--min-detections", type=int, default=1,
                   help="vendors that must say 'malicious' to list an IP (default 1)")
    p.add_argument("--internal-ranges", default=str(BASE_DIR / "internal_ranges.txt"),
                   help="file of extra CIDR ranges to treat as internal (default: internal_ranges.txt)")
    p.add_argument("--screenshot", choices=["auto", "vt", "card", "none"], default="auto",
                   help="auto = real VT page, fall back to evidence card (default); "
                        "vt = VT page only; card = evidence card only; none = skip")
    p.add_argument("--show-browser", action="store_true",
                   help="show the browser window (use if VT shows a captcha; solve it within --vt-wait)")
    p.add_argument("--browser", default="msedge", help="browser channel: msedge (default), chrome, or '' for bundled Chromium")
    p.add_argument("--vt-wait", type=int, default=30, help="seconds to wait for the VT page (solve captcha in this time)")
    p.add_argument("--crop-height", type=int, default=900, help="pixel height of the VT page crop")
    p.add_argument("--img-width", type=int, default=460, help="screenshot width inside the Excel file (px)")
    p.add_argument("--interval", type=float, default=FREE_TIER_INTERVAL,
                   help="seconds between calls per key (15.5 = free tier)")
    p.add_argument("--cache-hours", type=float, default=24, help="reuse cached lookups younger than this")
    return p.parse_args()


def make_scan_dir(output: Path) -> tuple[Path, str]:
    """output/ip_blocklist_29_sep, then ip_blocklist_29_sep_2, _3 ... for later scans that day."""
    now = dt.datetime.now()
    base = f"ip_blocklist_{now.day:02d}_{now.strftime('%b').lower()}"
    name, n = base, 1
    while (output / name).exists():
        n += 1
        name = f"{base}_{n}"
    return output / name, name


def main():
    args = parse_args()
    all_ips = load_ips(args.input, args.ips)
    if not all_ips:
        sys.exit("No IPs found. Use -i <file> or list IPs as arguments.")

    extra_nets = load_internal_ranges(Path(args.internal_ranges))
    internal = [ip for ip in all_ips if is_internal(ip, extra_nets)]
    internal_set = set(internal)
    ips = [ip for ip in all_ips if ip not in internal_set]
    print(f"{len(all_ips)} unique IPs found: {len(ips)} external to scan, {len(internal)} internal excluded")
    if not ips:
        sys.exit("Nothing to scan - every IP is internal.")

    api_keys = load_api_keys(args.api_key)
    out_dir, scan_name = make_scan_dir(Path(args.output))
    shots_dir, raw_dir = out_dir / "screenshots", out_dir / "raw"
    for d in (shots_dir, raw_dir):
        d.mkdir(parents=True, exist_ok=True)

    client = VTClient(api_keys, args.interval, BASE_DIR / ".cache", args.cache_hours)
    uncached = sum(1 for ip in ips if client.cached(ip) is None)
    rate = len(api_keys) * 60 / max(args.interval, 0.01)
    print(f"Using {len(api_keys)} API key(s) -> ~{rate:.0f} lookups/minute")
    if uncached:
        print(f"Estimated time: ~{uncached / rate:.1f} min for {uncached} uncached IPs")
    if uncached > 500 * len(api_keys):
        print(f"WARNING: {uncached} lookups exceed the free daily quota ({500 * len(api_keys)} with your keys).")

    records, interrupted = [], False
    try:
        for n, ip in enumerate(ips, start=1):
            status, body = client.lookup(ip)
            (raw_dir / (ip.replace(":", "_") + ".json")).write_text(json.dumps(body, indent=2), encoding="utf-8")
            rec = build_record(ip, status, body, args.min_detections)
            records.append(rec)
            extra = f" ({len(rec['flagged_by'])}/{rec['total']} malicious)" if rec["status"] == "MALICIOUS" else ""
            if rec["note"] and rec["status"] != "MALICIOUS":
                extra = f" - {rec['note']}"
            print(f"[{n}/{len(ips)}] {ip}: {rec['status']}{extra}")
            if rec["status"] == "Error" and not client.keys:
                print("All API keys are out of quota - stopping lookups.")
                break
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted - writing report for the IPs checked so far.")
    scanned = len(records)

    for ip in internal:
        rec = build_record(ip, 0, {}, args.min_detections)
        rec["status"], rec["note"] = "Internal", "Internal / private address - excluded from scan"
        records.append(rec)

    bad = [r for r in records if r["status"] == "MALICIOUS"]

    if bad and args.screenshot != "none" and not interrupted:
        print(f"\nCapturing proof screenshots for {len(bad)} malicious IPs ...")
        shooter = None
        try:
            shooter = Screenshotter(shots_dir, not args.show_browser, args.browser, args.vt_wait, args.crop_height)
            for rec in bad:
                path = shots_dir / (rec["ip"].replace(":", "_") + ".png")
                if args.screenshot in ("auto", "vt") and shooter.vt_page(rec["ip"], path):
                    rec["screenshot"], rec["screenshot_kind"] = str(path), "VirusTotal page"
                elif args.screenshot in ("auto", "card"):
                    shooter.card(rec, path)
                    rec["screenshot"], rec["screenshot_kind"] = str(path), "Evidence card (VT API data)"
                print(f"  {rec['ip']}: {rec['screenshot_kind'] or 'no screenshot'}")
        except KeyboardInterrupt:
            print("\nScreenshots interrupted - continuing with report.")
        except Exception as e:
            print(f"  screenshot step failed: {e}")
        finally:
            if shooter:
                shooter.close()

    counts = {s: sum(1 for r in records if r["status"] == s)
              for s in ("MALICIOUS", "Clean", "Not in VT", "Internal", "Error")}
    susp_only = sum(1 for r in records if r["status"] == "Clean" and r["suspicious"])
    run_info = {
        "Scan": scan_name,
        "Generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Input": args.input or "command line",
        "Unique IPs in input": len(all_ips),
        "Internal IPs excluded": len(internal),
        "External IPs scanned": f"{scanned} of {len(ips)}" + (" (interrupted)" if interrupted else ""),
        "Malicious (blocklisted)": counts["MALICIOUS"],
        "Clean": counts["Clean"],
        "Suspicious-only (not listed)": susp_only,
        "Not in VirusTotal": counts["Not in VT"],
        "Errors": counts["Error"],
        "Listing rule": f">= {args.min_detections} vendor(s) with an explicit 'malicious' verdict "
                        "('suspicious' ignored)",
        "API key usage": ", ".join(f"{k.label}: {k.used}" for k in client.keys + [k for k, _ in client.retired]),
        "Data source": "VirusTotal Public API v3",
    }

    write_excel(out_dir / f"{scan_name}.xlsx", records, run_info, args.img_width)
    write_html(out_dir / f"{scan_name}.html", records, run_info)
    (out_dir / f"{scan_name}.txt").write_text("\n".join(r["ip"] for r in bad) + ("\n" if bad else ""),
                                              encoding="utf-8")

    print(f"\nDone. {counts['MALICIOUS']} malicious / {scanned} external IPs scanned.")
    print(f"Scan folder: {out_dir}")
    print(f"  {scan_name}.xlsx, {scan_name}.html, {scan_name}.txt, screenshots/, raw/")


if __name__ == "__main__":
    main()
