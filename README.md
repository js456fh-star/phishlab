# Operation PAPER LANTERN — QR Phishing → AiTM Token Theft → BEC
### A self-contained SOC investigation lab

[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](tools/test_triage.py)
[![stdlib only](https://img.shields.io/badge/deps-stdlib%20only-blue)](tools/triage.py)
[![TLP](https://img.shields.io/badge/scenario-fictional-lightgrey)](#safety)

An end-to-end, **fully reproducible** blue-team case: a QR-code ("quishing")
phishing email leads to an **adversary-in-the-middle session-token theft** that
defeats MFA, followed by account takeover, a **stealth inbox rule**, and a
**business email compromise (BEC)** against Accounts Payable. You investigate it
with a custom, dependency-free triage toolkit, write detections, and produce an
incident report.

Built to show, in one repo, the skills a SOC/IR role actually tests:
**email forensics · log correlation · ATO analysis · detection engineering
(Sigma + KQL) · IOC extraction · MITRE ATT&CK mapping · incident reporting.**

---

## Why this scenario is different
Most phishing labs stop at "the email has a bad link." This one chains the
*modern* attack that real SOCs struggle with in 2026:

- **Quishing** — the payload is a **QR code**, so it jumps to a personal phone
  and skips the email gateway's URL sandbox entirely.
- **MFA is satisfied, then made irrelevant** — an AiTM proxy relays the live
  MFA code and steals the **session token**; the token is replayed from another
  country with **no MFA prompt**.
- **"All auth passed" is the trap** — SPF/DKIM/DMARC pass for a **typosquat**
  domain. The lab teaches you to distrust green checkmarks.
- **Post-ATO tradecraft** — a near-invisible inbox rule (`"."`) hides the
  fraud, plus silent external forwarding.

---

## Quick start
```bash
# no installation required — Python 3 standard library only
python3 -I tools/triage.py all        # full investigation
python3 -I tools/triage.py header     # just the email scoring
python3 -I tools/triage.py timeline   # merged timeline + impossible-travel
python3 -I tools/triage.py iocs       # indicators + ATT&CK
python3 -I tools/test_triage.py       # self-tests
```
`-I` runs Python in isolated mode (ignores the working dir on import) — good
hygiene when working near untrusted evidence.

---

## What the toolkit does
`tools/triage.py` ingests the `/evidence` folder and produces:
- **Weighted, explainable email scoring** (typosquat edit-distance, quishing,
  AiTM infra, auth-for-wrong-domain, urgency…) → verdict out of 120.
- **Unified UTC timeline** merging gateway trace + Entra sign-ins + M365 audit.
- **Impossible-travel detection** via haversine country centroids.
- **Defanged IOC table** mapped to MITRE ATT&CK.

Sample verdict:
```
Email verdict    : MALICIOUS (115/120)
Account j.okafor : COMPROMISED — confirmed ATO via AiTM token theft
Business impact  : BEC in progress — AP targeted for bank-detail change
```

---

## Repo layout
```
phishlab/
├── README.md
├── evidence/                     # the case data you investigate (all defanged)
│   ├── emails/                   # lure .eml copy, decoded QR payload, user report
│   ├── logs/                     # email gateway trace, Entra sign-ins, M365 audit
│   ├── intel/iocs.csv            # indicators of compromise
│   └── chain_of_custody.csv      # evidence integrity record
├── tools/
│   ├── triage.py                 # the investigation CLI (stdlib only)
│   └── test_triage.py            # self-tests
├── detections/
│   ├── sigma/                    # inbox-rule + AiTM-replay Sigma rules
│   └── kql/hunt_pack.kql         # 5 Sentinel/Defender hunting queries
├── report/
│   └── incident_report_PL-2026-1020.md   # full IR writeup
└── docs/
    ├── WALKTHROUGH.md            # step-by-step solution / how to run the lab
    └── containment.md            # IR runbook: Graph/Exchange PowerShell steps
```

## For your resume
> **Built a reproducible SOC investigation lab simulating a QR-phishing →
> adversary-in-the-middle MFA-token-theft → BEC attack chain. Developed a
> dependency-free Python triage toolkit (weighted email scoring, log
> correlation, impossible-travel detection, MITRE ATT&CK mapping), authored
> Sigma and KQL detections, and produced a full incident report.**

See `docs/WALKTHROUGH.md` for the guided investigation and `report/` for the
finished writeup.

---

## <a name="safety"></a>Safety & scope
Everything here is **fictional and inert**, intended solely for defensive
training:
- The company, users, and domains do not exist. IPs are **RFC 5737**
  documentation ranges; the phishing host does not resolve.
- All URLs/domains are **defanged** (`hxxps://`, `domain[.]com`).
- There is **no phishing email generator, no QR payload builder, and no
  attacker tooling** in this repo — only the defender-side evidence and
  analysis. Use it to learn detection and response, nothing else.
