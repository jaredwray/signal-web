#!/usr/bin/env python3
"""LIVE (opt-in) diagnostic of how Signal's servers treat browser-style requests.

NOT browser evidence. Browsers cannot reach these hosts at all (untrusted
certificate), so this uses curl with ONLY Signal's pinned root as trust anchor
(no verification is disabled) to see what would happen *after* TLS:

  * CORS preflights (OPTIONS) for requests a browser client would need;
  * whether a WebSocket upgrade carrying a browser Origin header is accepted;
  * which CORS headers, if any, accompany ordinary responses (and Alt-Svc).

One request per case, no credentials. The provisioning upgrade is closed after
the response headers arrive.  Usage:
  SIGNAL_WEB_LIVE=1 python3 tools/server_behavior_diagnostic.py
Writes evidence/live/server-behavior-diagnostic.json.
"""
import base64
import datetime
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent / "data" / "signal-messenger-root-2022.pem"
ORIGIN = "http://localhost:8080"

if os.environ.get("SIGNAL_WEB_LIVE") != "1":
    sys.exit("This contacts Signal servers. Re-run with SIGNAL_WEB_LIVE=1.")

CASES = [
    {"name": "preflight PUT /v1/devices/link (registration)", "method": "OPTIONS",
     "url": "https://chat.signal.org/v1/devices/link",
     "headers": {"Origin": ORIGIN, "Access-Control-Request-Method": "PUT",
                 "Access-Control-Request-Headers": "authorization,content-type"}},
    {"name": "GET /v1/certificate/delivery with Origin, no credentials", "method": "GET",
     "url": "https://chat.signal.org/v1/certificate/delivery", "headers": {"Origin": ORIGIN}},
    {"name": "WebSocket upgrade /v1/websocket/provisioning/ with browser Origin", "method": "GET",
     "url": "https://chat.signal.org/v1/websocket/provisioning/", "websocket": True,
     "headers": {"Origin": ORIGIN}},
    {"name": "WebSocket upgrade /v1/websocket/ (chat) with Origin, no credentials", "method": "GET",
     "url": "https://chat.signal.org/v1/websocket/", "websocket": True,
     "headers": {"Origin": ORIGIN}},
    {"name": "preflight POST cdn3 TUS upload", "method": "OPTIONS",
     "url": "https://cdn3.signal.org/attachments",
     "headers": {"Origin": ORIGIN, "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "authorization,tus-resumable,upload-length,upload-metadata"}},
    {"name": "GET cdn2 attachment path with Origin", "method": "GET",
     "url": "https://cdn2.signal.org/attachments/probe-nonexistent", "headers": {"Origin": ORIGIN}},
    {"name": "GET cdn3 attachment path with Origin", "method": "GET",
     "url": "https://cdn3.signal.org/attachments/probe-nonexistent", "headers": {"Origin": ORIGIN}},
]


def run(case):
    cmd = ["curl", "-sS", "--http1.1", "-o", "/dev/null", "-D", "-", "--max-time", "8",
           "--cacert", str(ROOT), "-X", case["method"], case["url"]]
    headers = dict(case["headers"])
    if case.get("websocket"):
        headers.update({
            "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
        })
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
    # curl -D prints the proxy's CONNECT response first (when a proxy is used);
    # keep only the final header block, which is the origin server's response.
    starts = [i for i, l in enumerate(lines) if l.startswith("HTTP/")]
    lines = lines[starts[-1]:] if starts else lines
    status = lines[0] if starts else None
    keep = ("access-control-", "alt-svc", "vary", "upgrade", "connection", "sec-websocket-accept",
            "cross-origin-resource-policy", "x-signal-timestamp")
    response_headers = sorted({l.split(":", 1)[0].lower() + ":" + l.split(":", 1)[1].strip()
                               for l in lines if ":" in l and l.lower().startswith(keep)})
    return {
        "request": {"method": case["method"], "url": case["url"], "headers": case["headers"],
                    "websocket_upgrade": bool(case.get("websocket"))},
        "status_line": status,
        "selected_response_headers": response_headers,
        "curl_exit": res.returncode,  # 28 = timed out after a 101 (socket left open), expected for upgrades
        "curl_error": res.stderr.strip()[:200] or None,
    }


def main():
    out = {
        "kind": "server-behavior-diagnostic",
        "label": "LIVE non-browser diagnostic (curl trusting only Signal's pinned root); not browser evidence",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "trust_anchor": "tools/data/signal-messenger-root-2022.pem (no verification disabled)",
        "via_proxy": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
        "cases": {},
    }
    for case in CASES:
        r = run(case)
        out["cases"][case["name"]] = r
        print(f"{case['name']}\n    {r['status_line']}  {'; '.join(r['selected_response_headers']) or '(no CORS/upgrade headers)'}")
    path = pathlib.Path(__file__).resolve().parent.parent / "evidence" / "live" / "server-behavior-diagnostic.json"
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
