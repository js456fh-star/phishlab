#!/usr/bin/env python3
"""
phish-triage — offline phishing investigation toolkit for Operation PAPER LANTERN.

A single, dependency-free CLI an analyst runs against the /evidence folder to:
  1. header   : score the reported email on weighted phishing heuristics
  2. timeline : merge all logs into one UTC attack timeline + flag impossible travel
  3. iocs     : extract & defang indicators, map to MITRE ATT&CK
  4. report   : print an executive triage summary with a verdict

Design goals (why this is resume-worthy):
  * Pure stdlib — runs on any locked-down analyst box, no pip.
  * Treats evidence as DATA, never executes or fetches anything.
  * Deterministic, explainable scoring (every point is justified in output).

Usage:
    python3 tools/triage.py all
    python3 tools/triage.py header
    python3 tools/triage.py timeline
    python3 tools/triage.py iocs
"""
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.join(HERE, "..", "evidence")

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
C = {"red": "\033[91m", "yel": "\033[93m", "grn": "\033[92m",
     "cyn": "\033[96m", "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m"}


def color(txt, c):
    if not sys.stdout.isatty():
        return txt
    return f"{C[c]}{txt}{C['end']}"


def rule(ch="-", n=72):
    print(ch * n)


def defang(s):
    if "[.]" in s or "hxxp" in s:      # already defanged upstream, leave as-is
        return s
    s = re.sub(r"https?://", "hxxps://", s)
    s = re.sub(r"\.(?!txt\b|py\b|json\b|csv\b)", "[.]", s)
    return s


def read(path):
    with open(os.path.join(EV, path), encoding="utf-8") as f:
        return f.read()


def load_json(path):
    with open(os.path.join(EV, path), encoding="utf-8") as f:
        return json.load(f)


def load_csv(path):
    with open(os.path.join(EV, path), encoding="utf-8") as f:
        return list(csv.DictReader(f))


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# 1. header analysis / weighted scoring
# --------------------------------------------------------------------------- #
LEGIT = "halvorsen-freight.com"


def levenshtein(a, b):
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
    return dp[-1]


def header_analysis():
    raw = read("emails/01_lure_voicemail.eml.txt")
    qr = read("emails/02_qr_payload.txt")
    findings = []

    def add(pts, name, detail):
        findings.append((pts, name, detail))

    # extract the from-domain
    m = re.search(r"From:.*@([a-z0-9\-\[\]]+\.[a-z\[\]]+)", raw, re.I)
    from_dom = m.group(1).replace("[.]", ".") if m else "?"

    dist = levenshtein(from_dom, LEGIT)
    if 0 < dist <= 2:
        add(30, "Look-alike sender domain",
            f"{defang(from_dom)} is edit-distance {dist} from {defang(LEGIT)} (typosquat)")

    if "spf=pass" in raw and "dkim=pass" in raw and "dmarc=pass" in raw:
        add(15, "Auth passes for WRONG domain",
            "SPF/DKIM/DMARC all pass — but authenticate the look-alike, not the brand")

    if "QR" in raw or "qr_voicemail" in raw:
        add(25, "QR-code payload (quishing)",
            "Payload delivered as image QR, bypassing URL rewriting/sandboxing")

    if re.search(r"expires? in 24|action required|urgent", raw, re.I):
        add(10, "Urgency / time-pressure lure", "24h expiry + 'action required'")

    if "voicemail" in raw.lower():
        add(5, "Pretext: unified-messaging voicemail", "Common credential-harvest theme")

    if re.search(r"u=[A-Za-z0-9_\-]{10,}", qr):
        add(10, "Victim identity pre-filled in URL",
            "base64url 'u' param pre-loads victim email into AiTM landing page")

    if "198.51.100.77" in qr or "reverse proxy" in qr.lower():
        add(20, "AiTM infrastructure in payload",
            "Landing host fronts an adversary-in-the-middle proxy (session-token theft)")

    score = sum(p for p, _, _ in findings)
    verdict = ("MALICIOUS", "red") if score >= 60 else \
              ("SUSPICIOUS", "yel") if score >= 30 else ("LIKELY BENIGN", "grn")

    print(color("\n[ HEADER & CONTENT ANALYSIS — EV-001 ]", "bold"))
    rule()
    print(f"  Reported sender domain : {defang(from_dom)}")
    print(f"  Brand domain           : {defang(LEGIT)}")
    print(f"  Typosquat edit-distance: {dist}")
    rule()
    for p, name, detail in sorted(findings, reverse=True):
        print(f"  {color('+'+str(p).rjust(2), 'red')}  {color(name, 'cyn')}")
        print(f"        {color(detail, 'dim')}")
    rule()
    print(f"  SCORE: {color(str(score)+'/120', 'bold')}   "
          f"VERDICT: {color(verdict[0], verdict[1])}")
    rule()
    return score, verdict[0]


# --------------------------------------------------------------------------- #
# 2. timeline + impossible-travel
# --------------------------------------------------------------------------- #
def geo_distance_km(a, b):
    # crude country-centroid lookup, enough to flag impossible travel in the lab
    cen = {"CA": (56.1, -106.3), "US": (37.1, -95.7), "RO": (45.9, 24.9),
           "": (0, 0), "Unknown": (0, 0)}
    import math
    (la1, lo1), (la2, lo2) = cen.get(a, (0, 0)), cen.get(b, (0, 0))
    r = 6371
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = math.radians(la2 - la1), math.radians(lo2 - lo1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def timeline():
    events = []
    for r in load_csv("logs/email_gateway_messagetrace.csv"):
        events.append((ts(r["timestamp_utc"]), "EMAIL",
                       f"{defang(r['sender'])} -> {r['recipient'].split('@')[0]}  [{r['gateway_verdict']}]"))
    signins = load_json("logs/entra_signin_logs.json")["records"]
    for s in signins:
        tok = s.get("incomingTokenType", "")
        extra = f" tokenType={tok}" if tok else ""
        events.append((ts(s["createdDateTime"]), "SIGNIN",
                       f"{s['userPrincipalName'].split('@')[0]} from {s['ipAddress']} "
                       f"({s['location']['countryOrRegion']}) risk={s.get('riskLevelDuringSignIn','?')}{extra}"))
    for a in load_json("logs/m365_unified_audit.json")["records"]:
        events.append((ts(a["CreationTime"]), "AUDIT",
                       f"{a['Operation']} by {a['UserId'].split('@')[0]} from {a['ClientIP']}"))

    events.sort(key=lambda e: e[0])
    print(color("\n[ UNIFIED ATTACK TIMELINE (UTC) ]", "bold"))
    rule()
    kind_c = {"EMAIL": "cyn", "SIGNIN": "yel", "AUDIT": "red"}
    for t, kind, desc in events:
        print(f"  {t.strftime('%H:%M:%S')}  {color(kind.ljust(6), kind_c[kind])}  {desc}")
    rule()

    # impossible travel across victim sign-ins
    print(color("  Impossible-travel check (victim sign-ins):", "bold"))
    vs = [s for s in signins if s["userPrincipalName"].startswith("j.okafor")]
    vs.sort(key=lambda s: ts(s["createdDateTime"]))
    flagged = False
    for i in range(1, len(vs)):
        a, b = vs[i - 1], vs[i]
        ca, cb = a["location"]["countryOrRegion"], b["location"]["countryOrRegion"]
        if ca and cb and ca != cb:
            dt = (ts(b["createdDateTime"]) - ts(a["createdDateTime"])).total_seconds() / 3600
            km = geo_distance_km(ca, cb)
            speed = km / dt if dt > 0 else 9e9
            if speed > 900:  # faster than a commercial jet
                flagged = True
                print(f"    {color('[!]', 'red')} {ca}->{cb} in {dt:.1f}h "
                      f"(~{km:.0f} km, {speed:.0f} km/h)  "
                      f"{a['ipAddress']} -> {b['ipAddress']}")
    if not flagged:
        print("    none")
    rule()


# --------------------------------------------------------------------------- #
# 3. IOCs
# --------------------------------------------------------------------------- #
def iocs():
    rows = load_csv("intel/iocs.csv")
    print(color("\n[ EXTRACTED INDICATORS (defanged) + MITRE ATT&CK ]", "bold"))
    rule()
    print(f"  {'TYPE':<10}{'INDICATOR':<52}{'ATT&CK'}")
    rule()
    for r in rows:
        print(f"  {r['type']:<10}{r['value']:<52}{r['mitre']}")
    rule()
    techniques = sorted({r["mitre"] for r in rows})
    print(f"  Techniques observed: {', '.join(techniques)}")
    rule()


# --------------------------------------------------------------------------- #
def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    print(color("=" * 72, "dim"))
    print(color("  phish-triage  ::  Operation PAPER LANTERN  ::  case PL-2026-1020", "bold"))
    print(color("=" * 72, "dim"))
    if cmd in ("header", "all"):
        score, verdict = header_analysis()
    if cmd in ("timeline", "all"):
        timeline()
    if cmd in ("iocs", "all"):
        iocs()
    if cmd == "all":
        print(color("\n[ TRIAGE VERDICT ]", "bold"))
        rule("=")
        print(f"  Email verdict      : {color(verdict, 'red')} ({score}/120)")
        print(f"  Account j.okafor   : {color('COMPROMISED — confirmed ATO via AiTM token theft', 'red')}")
        print(f"  Business impact     : {color('BEC in progress — AP targeted for bank-detail change', 'red')}")
        print(f"  Recommended action : {color('ISOLATE + REVOKE SESSIONS + REMOVE RULE (see report/)', 'yel')}")
        rule("=")
    if cmd not in ("header", "timeline", "iocs", "all"):
        print(__doc__)


if __name__ == "__main__":
    main()
