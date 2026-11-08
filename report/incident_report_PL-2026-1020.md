# Incident Report — Operation PAPER LANTERN
**Case ID:** PL-2026-1020 **Classification:** Internal / TLP:AMBER
**Severity:** High (P1) **Status:** Contained → Eradicated → Lessons Learned
**Author:** SOC Analyst (Tier 2) **Date:** 2026-10-21

> Training scenario. "Halvorsen Freight Co." and all indicators are fictional.
> IPs are RFC 5737 documentation ranges; no infrastructure is live.

---

## 1. Executive Summary
On 2026-10-20 an employee in Logistics (`j.okafor`) received a **QR-code
"voicemail" phishing email ("quishing")** from a look-alike domain. Scanning
the QR on a personal phone led to an **adversary-in-the-middle (AiTM) proxy**
that captured the user's credentials **and live session token**, defeating MFA.
The attacker **replayed the stolen token** from a foreign IP, took over the
mailbox, created a **hidden inbox rule** to suppress security/finance replies,
set **silent external forwarding**, and launched a **Business Email Compromise
(BEC)** attempt against Accounts Payable to redirect a vendor payment.

Time from delivery to account takeover: **~1h56m.** The intrusion was caught
because a second recipient reported the email and an analyst correlated the
report with high-risk sign-ins before the fraudulent payment was processed.

**Outcome:** No funds lost. One account compromised, remediated. Six-recipient
phishing wave neutralized.

---

## 2. Impact
| Dimension | Assessment |
|---|---|
| Accounts compromised | 1 (`j.okafor`) — confirmed token theft |
| Data accessed | Inbox + Sent Items read by attacker (MailItemsAccessed) |
| Financial | BEC attempt on AP; **blocked before payment** |
| Persistence | Hidden inbox rule + silent forwarding (both removed) |
| Lateral movement | None observed; no admin escalation |

---

## 3. Attack Timeline (UTC)
| Time | Phase | Event |
|---|---|---|
| 13:02 | Delivery | Quishing email delivered to 4 mailboxes from `halvorsen-frieght[.]com` (203.0.113.45) |
| 13:48 | Delivery (internal) | Victim forwards email internally asking "is this legit?" |
| 13:49 | Cred Access | AiTM proxy (198.51.100.77) completes MFA sign-in as victim — **token minted** |
| 14:11 | Detection seed | `r.castillo` reports the email via Report Phishing button |
| 14:58 | Initial Access | Stolen token **replayed** from 192.0.2.150 (RO), **no MFA**, risk=high |
| 14:59 | Collection | Attacker reads mailbox (MailItemsAccessed) |
| 15:01 | Defense Evasion | Hidden inbox rule `"."` → move finance/security mail to RSS Subscriptions |
| 15:20 | Impact (BEC) | Attacker emails AP (`a.lindqvist`) requesting vendor bank-detail change |
| 15:21 | Persistence | Silent external forwarding set to `external-vendor-payments@mail.halvorsen-frieght[.]com` |
| 16:40 | — | Victim's legitimate Toronto session active **concurrently** with RO session (confirms ATO) |

---

## 4. Analysis & Key Judgments
1. **"Auth passed" ≠ legitimate.** SPF/DKIM/DMARC all passed because the
   attacker correctly authenticated their **own** typosquat domain. The brand
   was never impersonated at the protocol level — only visually.
2. **QR code was the delivery innovation.** By moving the link into an image
   destined for a personal phone, the attacker bypassed the gateway's URL
   rewriting and sandbox detonation entirely. (MITRE **T1566.002**)
3. **MFA was satisfied, not bypassed, then made irrelevant.** The AiTM proxy
   relayed the real-time MFA code; the resulting **session token** was the
   crown jewel. Replay from a new country with `singleFactorAuthentication`
   and `incomingTokenType=primaryRefreshToken` is the fingerprint. (**T1557**)
4. **Impossible travel confirmed takeover.** US→RO at ~7,900 km/h between the
   proxy sign-in and the replay; RO session ran concurrently with the victim's
   real Toronto session.
5. **Inbox rule was for cover, not productivity.** A rule named `"."` that
   marks finance/fraud/security mail read and hides it in RSS Subscriptions is
   designed so the victim never sees a bank's or colleague's warning reply.
   (**T1564.008**)

---

## 5. MITRE ATT&CK Mapping
| Tactic | Technique | Evidence |
|---|---|---|
| Resource Dev | Acquire typosquat domain | `halvorsen-frieght[.]com` |
| Initial Access | T1566.002 Spearphishing Link (QR/quishing) | EV-001/002 |
| Credential Access | T1557 Adversary-in-the-Middle | Sign-in from 198.51.100.77 |
| Initial Access | T1078.004 Valid Accounts: Cloud | Token replay 192.0.2.150 |
| Collection | T1114.003 Email Forwarding Rule | Set-Mailbox forwarding |
| Defense Evasion | T1564.008 Hidden Inbox Rule | New-InboxRule `"."` |
| Impact | BEC / financial fraud | Send to AP |

---

## 6. Response Actions (what was done)
**Contain (T+0 to T+30m)**
- Revoked all `j.okafor` sessions/refresh tokens (`Revoke-MgUserSignInSession`; full steps in `docs/containment.md`).
- Forced password reset + re-registered MFA.
- Blocked sender domain + 3 IPs at gateway and firewall; quarantined the wave.

**Eradicate**
- Removed hidden inbox rule and the external-forwarding setting.
- Purged the phishing email from all 4 mailboxes (soft+hard delete).
- Confirmed no additional rules, OAuth app grants, or MFA methods added.

**Recover**
- Restored normal mail flow; verified AP did **not** action the bank change.
- Briefed AP team; re-confirmed vendor bank details out-of-band by phone.

---

## 7. Recommendations
| Priority | Control | Rationale |
|---|---|---|
| P1 | Enforce **phishing-resistant MFA** (FIDO2 / device-bound passkeys) | Defeats AiTM token theft at the root |
| P1 | Conditional Access: require **compliant/managed device** for mail | Replayed token from unmanaged Linux box would fail |
| P1 | Enable **token protection / continuous access evaluation** | Shrinks replay window, re-checks risk mid-session |
| P2 | Alert on **inbox rules** with stealth names or finance keywords | Deploy the Sigma/KQL rules in `/detections` |
| P2 | Block/scan **QR codes** in mail; user training on quishing | Closes the personal-device gap |
| P3 | **Dual-authorization + out-of-band callback** for bank-detail changes | Last line against BEC even if an account is lost |

---

## 8. Indicators of Compromise
See `evidence/intel/iocs.csv` (defanged). Highlights:
`halvorsen-frieght[.]com` · `voicemail-portal.halvorsen-frieght[.]com` ·
`203.0.113.45` · `198.51.100.77` · `192.0.2.150` ·
inbox rule name `"."` → RSS Subscriptions ·
forwarding `external-vendor-payments@mail.halvorsen-frieght[.]com`

---

## 9. Lessons Learned
- **What worked:** user reporting culture; fast log correlation; token revocation.
- **What didn't:** gateway trusted auth results without brand-similarity scoring;
  no device-bound session controls; QR payloads unscanned.
- **Dwell time:** ~2h from delivery to BEC — fast, but reporting + CAE-style
  controls would have pre-empted the replay entirely.
