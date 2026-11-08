# Containment & Eradication Runbook — PL-2026-1020

Response commands for the PAPER LANTERN scenario (AiTM token theft → hidden
inbox rule → BEC). Run in order. Every step has a **verify** check, because a
command that ran is not the same as a threat that's gone.

> Lab context: the tenant, users and domains are fictional. In a real incident,
> follow your org's change-approval process and record each action with a
> timestamp in the case log.

**Variables used below**
```powershell
$Victim  = "j.okafor@halvorsen-freight.com"
$Domain  = "halvorsen-frieght.com"           # typosquat (write defanged in reports)
$BadIPs  = "203.0.113.45","198.51.100.77","192.0.2.150"
```

**Modules**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser       # Entra ID
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Connect-MgGraph -Scopes "User.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All","Directory.Read.All"
Connect-ExchangeOnline
Connect-IPPSSession                                     # Purview (for purge)
```

---

## Phase 1 — Contain (target: first 30 minutes)

### 1.1 Kill the stolen session first
The attacker holds a valid token, so a password reset alone does **not** lock
them out. Revoke sessions before doing anything else.
```powershell
$u = Get-MgUser -UserId $Victim
Revoke-MgUserSignInSession -UserId $u.Id
```
**Verify:** new Entra sign-ins from `192.0.2.150` should now fail or stop.
Revocation can take a few minutes to reach every service.

### 1.2 Block sign-in while you work (optional, high-risk accounts)
```powershell
Update-MgUser -UserId $u.Id -AccountEnabled:$false
```
Re-enable in Phase 3 after the password reset and MFA re-registration.

### 1.3 Reset the password
Use a temporary password delivered **out of band** (phone/in person), not to
the compromised mailbox.
```powershell
$pw = @{ Password = "<generated-temp-password>"; ForceChangePasswordNextSignIn = $true }
Update-MgUser -UserId $u.Id -PasswordProfile $pw
```

### 1.4 Review MFA methods (attackers sometimes add their own)
```powershell
Get-MgUserAuthenticationMethod -UserId $u.Id |
  Select-Object Id, @{n="Type";e={$_.AdditionalProperties.'@odata.type'}}
```
Remove any method the user doesn't recognize, then have them re-register.

### 1.5 Block the infrastructure
```powershell
# Sender domain + URL host in Tenant Allow/Block List (Defender for Office 365)
New-TenantAllowBlockListItems -ListType Sender -Block -Entries $Domain -NoExpiration
New-TenantAllowBlockListItems -ListType Url    -Block -Entries "*.$Domain/*" -NoExpiration
```
Add the three IPs to the firewall/proxy deny list and an Entra **named
location** that a Conditional Access policy blocks.

---

## Phase 2 — Eradicate

### 2.1 Find and remove the hidden inbox rule
```powershell
Get-InboxRule -Mailbox $Victim |
  Select-Object Name, Identity, Enabled, MoveToFolder, MarkAsRead, SubjectOrBodyContainsWords
```
Look for the rule named `"."`. **Export it as evidence before deleting.**
```powershell
Get-InboxRule -Mailbox $Victim | Where-Object { $_.Name -eq "." } |
  Export-Clixml ".\EV-007_inboxrule.xml"
Get-InboxRule -Mailbox $Victim | Where-Object { $_.Name -eq "." } |
  ForEach-Object { Remove-InboxRule -Mailbox $Victim -Identity $_.Identity -Confirm:$false }
```
**Verify:** run `Get-InboxRule` again and confirm the rule is gone. Also check
the *RSS Subscriptions* folder — warning replies the victim never saw may be
sitting there.

### 2.2 Remove silent forwarding
```powershell
Get-Mailbox $Victim | Select-Object ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
Set-Mailbox $Victim -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false
```

### 2.3 Check for other persistence
```powershell
# Mail-client access the attacker may have added
Get-CASMailbox $Victim | Select-Object ActiveSyncEnabled, PopEnabled, ImapEnabled
Get-MobileDevice -Mailbox $Victim | Select-Object FriendlyName, DeviceOS, FirstSyncTime

# OAuth app consents granted by the victim
Get-MgUserOauth2PermissionGrant -UserId $u.Id
```
Remove anything created after 13:49 UTC on 2026-10-20 that the user can't
account for.

### 2.4 Purge the phishing wave from all mailboxes
```powershell
New-ComplianceSearch -Name "PL-2026-1020-purge" -ExchangeLocation All `
  -ContentMatchQuery 'from:voicemail@halvorsen-frieght.com AND received>=2026-10-20'
Start-ComplianceSearch -Identity "PL-2026-1020-purge"
Get-ComplianceSearch   -Identity "PL-2026-1020-purge" | Select-Object Status, Items   # expect 4 items
New-ComplianceSearchAction -SearchName "PL-2026-1020-purge" -Purge -PurgeType HardDelete
```
Also purge the BEC email the attacker sent to AP, and the victim's internal
forward to `r.castillo`.

### 2.5 Hunt for other victims
Run `detections/kql/hunt_pack.kql` queries 3–5 across **all** users for the
past 14 days. Any hit from the three IPs means you repeat Phase 1 for that user.

---

## Phase 3 — Recover

1. Re-enable the account (if disabled in 1.2) once password and MFA are reset.
2. Confirm with Accounts Payable that the bank-detail change was **not**
   actioned, and re-verify the vendor's details by a phone call to a number
   already on file, not one from the email.
3. Watch the account for 7 days: alert on any sign-in outside CA, and on any
   new inbox rule or forwarding change.
4. Update the case log and close with a lessons-learned review (see
   `report/incident_report_PL-2026-1020.md`, section 9).

---

## Quick checklist
- [ ] Sessions revoked (1.1)
- [ ] Password reset out of band (1.3)
- [ ] MFA methods reviewed (1.4)
- [ ] Domain / URL / IPs blocked (1.5)
- [ ] Inbox rule exported and removed (2.1)
- [ ] Forwarding removed (2.2)
- [ ] Persistence checked: devices, protocols, OAuth (2.3)
- [ ] Phishing wave + BEC email purged (2.4)
- [ ] Org-wide hunt run (2.5)
- [ ] AP confirmation + vendor callback (3.2)
- [ ] 7-day monitoring in place (3.3)
