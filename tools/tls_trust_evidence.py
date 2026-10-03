#!/usr/bin/env python3
"""LIVE (opt-in) TLS trust evidence for Signal's service hosts.

NOT browser evidence. This uses the openssl CLI to record which certificate
chain each host presents, and two public datasets to decide whether any
browser could trust it:

  * Certificate Transparency (Cert Spotter API): browsers (Chrome, Safari)
    require publicly trusted certificates to be CT-logged, so zero unexpired
    logged issuances for a name means no publicly trusted certificate exists.
  * CCADB "AllIncludedRootCertsCSV": the roots included by the Apple, Google
    Chrome, Microsoft and Mozilla root programs.

Usage:  SIGNAL_WEB_LIVE=1 python3 tools/tls_trust_evidence.py
If $HTTPS_PROXY is set, openssl tunnels through it with CONNECT; the recorded
issuer shows whether the tunnel was end to end.
Writes evidence/live/tls-trust-summary.json.
"""
import csv
import datetime
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request

HOSTS = [
    "chat.signal.org", "grpc.chat.signal.org", "storage.signal.org",
    "cdn.signal.org", "cdn2.signal.org", "cdn3.signal.org",
    "cdsi.signal.org", "svr2.signal.org", "svrb.signal.org",
    "updates.signal.org",  # control: publicly trusted
]
SIGNAL_ROOT_SHA256 = "DDB0F92BB95C8D6FD202EA6E8CC5CCD182B544F8CD696F47D580659DDC9DF65A"
SIGNAL_ROOT_PEM = pathlib.Path(__file__).resolve().parent / "data" / "signal-messenger-root-2022.pem"
CCADB_CSV = "https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances?domain={}&expand=dns_names&expand=issuer"

if os.environ.get("SIGNAL_WEB_LIVE") != "1":
    sys.exit("This contacts Signal servers and public CT/CCADB services. Re-run with SIGNAL_WEB_LIVE=1.")


def openssl_chain(host):
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    cmd = ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host,
           "-alpn", "http/1.1", "-showcerts", "-verify_return_error"]
    if proxy:
        cmd[2:2] = ["-proxy", urllib.parse.urlparse(proxy).netloc]
    out = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=30).stdout
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", out, re.S)
    certs = []
    for pem in pems:
        info = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256",
             "-ext", "subjectAltName"], input=pem, capture_output=True, text=True).stdout
        field = lambda name: (re.search(rf"^{name}=(.*)$", info, re.M) or [None, None])[1]
        certs.append({
            "subject": field("subject"),
            "issuer": field("issuer"),
            "not_before": field("notBefore"),
            "not_after": field("notAfter"),
            "sha256": (field("sha256 Fingerprint") or "").replace(":", ""),
            "san": ",".join(re.findall(r"DNS:([^,\s]+)", info)),
        })
    verify = (re.search(r"Verify return code: (.*)", out) or [None, "no handshake"])[1]
    # Does the presented leaf verify against Signal's private root alone
    # (no system roots)? Intermediates, if any, are taken from the chain.
    signal_verify = None
    if pems:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            leaf = pathlib.Path(d, "leaf.pem"); leaf.write_text(pems[0])
            inter = pathlib.Path(d, "inter.pem"); inter.write_text("\n".join(pems[1:]) or "")
            cmd = ["openssl", "verify", "-no-CApath", "-no-CAfile", "-trusted", str(SIGNAL_ROOT_PEM)]
            if len(pems) > 1:
                cmd += ["-untrusted", str(inter)]
            res = subprocess.run(cmd + [str(leaf)], capture_output=True, text=True)
            signal_verify = (res.stdout + res.stderr).strip().splitlines()[-1].replace(str(leaf), "leaf")
    return {
        "via_proxy": bool(proxy),
        "presented_chain": certs,
        "leaf_issuer": certs[0]["issuer"] if certs else None,
        "signal_root_in_chain": any(c["sha256"] == SIGNAL_ROOT_SHA256 for c in certs),
        "verify_against_system_store": verify,
        "verify_against_signal_root_only": signal_verify,
    }


def ct_unexpired(host):
    with urllib.request.urlopen(CERTSPOTTER.format(host), timeout=60) as r:
        rows = json.load(r)
    exact = [x for x in rows if host in x.get("dns_names", [])]
    return {
        "unexpired_logged_issuances": len(exact),
        "sample": [{"not_before": x["not_before"], "not_after": x["not_after"],
                    "issuer": x.get("issuer", {}).get("name")} for x in exact[:3]],
    }


def ccadb():
    with urllib.request.urlopen(CCADB_CSV, timeout=120) as r:
        text = r.read().decode("utf-8", "replace")
    rows = list(csv.DictReader(io.StringIO(text)))
    hits = [x for x in rows if x.get("SHA-256 Fingerprint", "").upper() == SIGNAL_ROOT_SHA256
            or "signal" in (x.get("CA Owner", "") + x.get("Certificate Name", "")).lower()]
    return {"source": CCADB_CSV, "included_roots_listed": len(rows),
            "programs": ["Apple", "Google Chrome", "Microsoft", "Mozilla"],
            "signal_root_matches": hits}


def main():
    hosts = {}
    for host in HOSTS:
        entry = {"tls": openssl_chain(host)}
        try:
            entry["certificate_transparency"] = ct_unexpired(host)
        except Exception as e:  # noqa: BLE001 - record and continue
            entry["certificate_transparency"] = {"error": str(e)}
        hosts[host] = entry
        print(f"{host:22} leaf issuer: {entry['tls']['leaf_issuer']} | signal root in chain: "
              f"{entry['tls']['signal_root_in_chain']} | verifies vs Signal root: "
              f"{entry['tls']['verify_against_signal_root_only']} | CT unexpired: "
              f"{entry['certificate_transparency'].get('unexpired_logged_issuances')}")
    summary = {
        "kind": "tls-trust-evidence",
        "label": "LIVE non-browser diagnostic (openssl + public CT/CCADB data); not browser evidence",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "signal_root_sha256": SIGNAL_ROOT_SHA256,
        "hosts": hosts,
        "ccadb": ccadb(),
    }
    print(f"CCADB: {summary['ccadb']['included_roots_listed']} included roots, "
          f"Signal root matches: {len(summary['ccadb']['signal_root_matches'])}")
    out = pathlib.Path(__file__).resolve().parent.parent / "evidence" / "live" / "tls-trust-summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
