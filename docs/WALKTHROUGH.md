# Lab Walkthrough — Operation PAPER LANTERN

A guided investigation. Try each step yourself before reading the answer.
Everything is offline and defanged; you never need to touch live infrastructure.

---

## Scenario brief
You are a Tier-2 SOC analyst at **Halvorsen Freight Co.** A user reported a
suspicious "voicemail" email. Figure out what happened, how bad it is, and what
to do. Start at `evidence/`.

---

## Step 1 — Triage the reported email
**Task:** Open `evidence/emails/01_lure_voicemail.eml.txt`. Is it malicious?
Which domain really sent it?

<details><summary>Answer</summary>

Sender is `halvorsen-frieght[.]com` — a **typosquat** (the real brand is
`halvorsen-freight.com`, with `ei`/`ie` swapped). SPF/DKIM/DMARC all **pass**,
but for the look-alike domain — a classic misdirection. The payload is a **QR
code**, not a link (quishing). Run:
```bash
python3 -I tools/triage.py header   # → MALICIOUS 115/120
```
</details>

## Step 2 — Decode the QR payload safely
**Task:** What does the QR code point to? How would you decode it without risk?

<details><summary>Answer</summary>

See `evidence/emails/02_qr_payload.txt`. Decode the image **offline** (e.g.
`zbarimg` on an isolated VM) — never scan it on a phone. The URL points to
`voicemail-portal.halvorsen-frieght[.]com` (198.51.100.77) with the victim's
email base64url-encoded in the `u=` parameter. That host is an **AiTM reverse
proxy**. Pivot on the IP/domain via passive DNS; do **not** browse it.
</details>

## Step 3 — Did anyone fall for it? Build the timeline
**Task:** Correlate the email with sign-in and audit logs. When was the account
compromised?

<details><summary>Answer</summary>

```bash
python3 -I tools/triage.py timeline
```
At 13:49 the AiTM proxy (198.51.100.77) completes an MFA sign-in as the victim
— the token is minted. At 14:58 that token is **replayed** from 192.0.2.150
(Romania) with `singleFactorAuthentication` and
`incomingTokenType=primaryRefreshToken` — **no MFA prompt**. The tool flags
**impossible travel** (US→RO ~7,900 km/h) and the attacker's RO session runs
concurrently with the victim's real Toronto session → **confirmed takeover**.
</details>

## Step 4 — What did the attacker do inside?
**Task:** Read `evidence/logs/m365_unified_audit.json`. Find persistence and
impact.

<details><summary>Answer</summary>

- **New-InboxRule** named `"."` → moves any mail containing
  invoice/payment/bank/fraud/security to *RSS Subscriptions*, marked read
  (hide-the-evidence, **T1564.008**).
- **Set-Mailbox** silent external forwarding to the look-alike domain.
- **Send** to Accounts Payable (`a.lindqvist`) requesting a vendor
  **bank-detail change** — the BEC payload.
</details>

## Step 5 — Extract IOCs & map ATT&CK
```bash
python3 -I tools/triage.py iocs
```
Compare your list to `evidence/intel/iocs.csv`. You should have 3 IPs, 2
domains/hosts, 2 attacker emails, the inbox rule, and the techniques
T1566.002 / T1557 / T1078.004 / T1564.008 / T1114.003.

## Step 6 — Detect it next time
Review `detections/sigma/` and `detections/kql/hunt_pack.kql`. Each query maps
to a specific step above. Ask yourself: which single control would have broken
the chain earliest? (Hint: phishing-resistant, device-bound MFA / token
protection — see the report.)

## Step 7 — Write it up
Read `report/incident_report_PL-2026-1020.md`. Then try writing your own
executive summary in 5 sentences and compare.

---

## Extend the lab (ideas)
- Add a second victim who **didn't** scan, and tune your detections to avoid the
  false positive.
- Add an OAuth illicit-consent grant as an alternate persistence path.
- Port the Sigma rules to your SIEM of choice and test them against the logs.
- Run through `docs/containment.md` and write down which step you'd do first if
  you only had five minutes (answer: revoke sessions — 1.1).
