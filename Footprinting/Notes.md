# 01 — Footprinting

**Footprinting** is the first actual stage of Enumeration after discovering the open ports (a normal Nmap scan). Here we go deeper into each service individually, collect as much information as possible, and identify potential weaknesses before the exploitation phase (Exploitation).

> ⚠️ All commands and techniques here are for authorized environments only (Labs / CTFs / documented tests).

## 📑 Table of Contents

- [FTP (Port 21)](#ftp-port-21)
- [SMB (Ports 139, 445)](#smb-ports-139-445)
- [NFS (Ports 111, 2049)](#nfs-ports-111-2049)
- [DNS (Port 53)](#dns-port-53)
- [SMTP (Ports 25, 587, 465)](#smtp-ports-25-587-465)
- [IMAP and POP3](#imap-and-pop3)
- [SNMP (Ports 161, 162)](#snmp-ports-161-162)
- [MySQL (Port 3306)](#mysql-port-3306)
- [MSSQL (Port 1433)](#mssql-port-1433)
- [Oracle TNS (Port 1521)](#oracle-tns-port-1521)
- [IPMI (Port 623)](#ipmi-port-623)
- [Linux Remote Management Protocols](#linux-remote-management-protocols) 
  - [SSH (Port 22)](#ssh-port-22)
  - [Rsync (Port 873)](#rsync-port-873)
  - [R-Services (Ports 512-514)](#r-services-ports-512-514)
- [Windows Remote Management Protocols](#windows-remote-management-protocols) 
  - [RDP (Port 3389)](#rdp-port-3389)
  - [WinRM (Ports 5985, 5986)](#winrm-ports-5985-5986)
  - [WMI (Port 135)](#wmi-port-135)
- [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet)

---

## FTP (Port 21)

File Transfer Protocol (File Transfer Protocol). FTP usually runs on:

```
TCP 21

```

Port 21 is called **control channel**, where commands like these are sent:

```
ls
get
put
cd
pwd

```

There is another channel for data (**data channel**) usually associated with port 20 (in Active Mode) or a random port depending on Passive Mode.

> **FTP = file transfer service | Port 21 = the main control port for FTP**

### Active FTP vs Passive FTP

**Active Mode**: the client connects to the server on port 21, and then the **server** tries to open a connection back to the client (from port 20) to transfer the data. the problem: if the client is behind a firewall or NAT, the incoming connection from the server may be blocked.

**Passive Mode**: the server tells the client "connect to me on this port so we can transfer the data", meaning the **client** starts the data connection, so it usually passes through the firewall more easily.

> **Active = the server connects back to the client | Passive = the client opens the data connection**

if you see a message like `Consider using PASV` the FTP client is suggesting that you use Passive mode.

### Anonymous FTP

One of the most important points in Footprinting. sometimes the server allows anyone to log in without a real username/password:

```
username: anonymous
password: anonymous (or any email, or empty)

```

Example:

```
ftp 10.129.14.136
Name: anonymous
Password: anonymous

```

if it succeeds and you get `230 Login successful` the server allows anonymous login, and you can do:

```
ls      # list files
get     # download a file
put     # upload a file (if allowed)

```

### TFTP (briefly)

**TFTP = Trivial File Transfer Protocol**, a much simpler version of FTP, and it runs on **UDP 69**.

| FTP TFTP                            |                                                        |
| ----------------------------------- | ------------------------------------------------------ |
| uses TCP                          | uses UDP                                             |
| has login/authentication            | usually has no authentication                             |
| supports more commands                     | very simple                                              |
| supports directory listing             | does not support directory listing                              |
| more commonly used as a general file transfer service | usually used inside local networks (such as firmware loading) |

TFTP commands: `connect` (connect), `get` (download), `put` (upload), `status` (status), `quit` (exit), `verbose` (more details).

> TFTP does not have authentication or directory listing, so it is usually used only on protected local networks (such as PXE booting).

### vsFTPd

one of the most common FTP servers on Linux, short for **Very Secure FTP Daemon**. configuration file:

```
/etc/vsftpd.conf

```

to show the settings without comments:

```
cat /etc/vsftpd.conf | grep -v "#"

```

- `cat /etc/vsftpd.conf` → show the file
- `grep -v "#"` → hide any line containing `#` (because lines containing `#` are usually comments)

### Important vsFTPd Settings

| Setting — Meaning                |                                                                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `anonymous_enable=YES`        | Does it allow anonymous login?                                                                                         |
| `local_enable=YES`            | allows local system users to log in to FTP with their accounts                                                               |
| `write_enable=YES`            | allows write commands: `STOR` (upload), `DELE` (delete), `MKD` (create directory), `RMD` (delete directory), `RNFR/RNTO` (rename) |
| `anon_upload_enable=YES`      | allows anonymous to upload files                                                                                |
| `anon_mkdir_write_enable=YES` | allows anonymous to create new directories                                                                           |
| `no_anon_password=YES`        | allows anonymous to log in without being asked for a password                                                               |
| `anon_root=/path`             | specifies where anonymous logs in (Example: `anon_root=/home/username/ftp`)                                      |
| `ssl_enable=YES/NO`           | whether the connection is encrypted with TLS/SSL or plain text                                                                        |

### Dangerous Settings (dangerous when combined)

| Setting — Description                  |                                                                    |
| ------------------------------ | ------------------------------------------------------------------ |
| `anonymous_enable=YES`         | allows anonymous login                                               |
| `anon_upload_enable=YES`       | allows anonymous to upload files                                       |
| `anon_mkdir_write_enable=YES`  | allows for  anonymous creates directories                                      |
| `no_anon_password=YES`         | no password is required for anonymous                                   |
| `anon_root=/home/username/ftp` | anonymous path                                                     |
| `write_enable=YES`             | enables write commands (STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, SITE) |

### Manual Login and Important FTP Commands

```
ftp 10.129.14.136

```

if you see `220 Welcome to the HTB Academy vsFTP service.` this is called **banner**, and it may give you: service name, server type, sometimes the version.

Useful commands after login:

```
ls          # list files
status      # connection status (Mode, Type, Passive/Active...)
debug       # enable details of sent commands
trace       # trace the packets/commands
ls -R       # recursive listing (requires ls_recurse_enable=YES on the server)
get "file name.txt"   # or: get file\ name.txt (the \ before the space)

```

### Download all files at once with wget

```
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

```

- `-m` → mirror, download a copy of everything available
- `--no-passive` → do not use passive mode
- `ftp://anonymous:anonymous@IP` → log in with the anonymous username and password

After downloading, wget creates a folder named after the target IP with the files inside it..

### Footprinting with Nmap

```
sudo nmap -sV -p21 -sC -A 10.129.14.136

```

- `-sV` detect the service version | `-p21` scan port 21 only | `-sC` run default scripts | `-A` aggressive scan (version + OS detection + scripts + traceroute)

Example output:

```
21/tcp open ftp vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed
|_ -rw-r--r-- 1 0 0 2726... flag.txt [NSE: writeable]

```

- the port is open, server vsftpd 2.0.8+
- `ftp-anon: Anonymous FTP login allowed` → anonymous is available
- `[NSE: writeable]` → the file/folder is writable (possible upload/modification)

### Practical Example

```
# 1) scan the port and find the banner and version
sudo nmap -sV -sC -p21 10.129.14.136

# 2) try anonymous login
ftp 10.129.14.136
# Name: anonymous / Password: anonymous

# 3) explore the files
ftp> ls -la
ftp> get "Important Notes.txt"

# 4) if the share is large, download everything at once
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

# 5) if write_enable is enabled, try uploading a test file (only in an authorized environment)
ftp> put test.txt

```

### Additional Information

- **CVE-2011-2523**: an old version of vsftpd (2.3.4) has a very famous backdoor — if the banner shows `vsftpd 2.3.4` this is a red flag worth checking with Metasploit (`exploit/unix/ftp/vsftpd_234_backdoor`).
- Brute force with Hydra if the password is unknown: 
  ```
  hydra -L users.txt -P passwords.txt ftp://10.129.14.136

  ```
- Alternative tool: `lftp` — client stronger than `ftp` normal and supports mirroring like wget.

---

## SMB (Ports 139, 445)

SMB (Server Message Block) a protocol for sharing files and printers over a network. you will usually find it on:

```
139/tcp   (NetBIOS over TCP/IP)
445/tcp   (SMB directly over TCP)

```

on Windows it is native, on Linux it runs through a program called **Samba**.

> SMB versions range from 1 to 3.1.1 — **SMBv1** is the most dangerous and contains some of the most famous vulnerabilities (such as EternalBlue/MS17-010), andit is always recommended to disable it.

### Samba Configuration File

```
/etc/samba/smb.conf

```

| Setting — Meaning          |                          |
| ----------------------- | ------------------------ |
| `[sharename]`           | share name             |
| `path`                  | folder location on the server |
| `browseable = yes`      | whether the share appears in the list  |
| `guest ok = yes`        | whether you can access it without a password |
| `read only = no`        | whether you can modify/upload       |
| `writable = yes`        | whether you have write permission     |
| `create mask = 0777`    | permissions for new files  |
| `directory mask = 0777` | permissions for new directories |

Most dangerous combination: `guest ok = yes` + `writable = yes` + `read only = no` + `browseable = yes` → anyone can access the share, and write or upload files without authentication.

### Listing the Shares

```
smbclient -N -L //10.129.14.128

```

`-L` list shares | `-N` without a password (anonymous/null session)

Example output:

```
Sharename       Type
---------       ----
print$          Disk
home            Disk
dev             Disk
notes           Disk
IPC$            IPC

```

### Connecting to a Specific Share

```
smbclient //10.129.14.128/notes -N

```

Important commands after login:

```
ls          # list files
get file    # download a file
put file    # upload a file (if allowed)
pwd         # current path
help        # all commands
exit        # exit
!ls         # run a command on your local machine, not on the server (! before any command)

```

> if the share needs credentials: `smbclient //IP/share -U username`

### Nmap with SMB

```
sudo nmap -sV -sC -p139,445 10.129.14.128

```

it may show you: `Samba smbd 4.6.2`, `Message signing enabled but not required`, NetBIOS name, SMB time.

> **Note:** Nmap alone is not enough in SMB enumeration — you need other tools and manual interaction.

### rpcclient

a very important tool for extracting information from SMB/RPC:

```
rpcclient -U "" 10.129.14.128

```

Most important rpcclient commands:

```
srvinfo              # server information
enumdomains          # list domains/workgroups
querydominfo         # domain information
netshareenumall      # list all shares
netsharegetinfo name # information about a specific share
enumdomusers         # list users
queryuser RID        # information about a specific user

```

Example:

```
rpcclient $> enumdomusers
user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]

```

### SMBMap

an easy tool that shows you the shares and your permissions on them:

```
smbmap -H 10.129.14.128

```

Example output:

```
notes    READ, WRITE
home     READ ONLY
print$   NO ACCESS

```

if you find `READ, WRITE` make that share a priority because you can read and write to it.

### Practical Example

```
# 1) Initial scan
sudo nmap -sV -sC -p139,445 10.129.14.128

# 2) list the available shares
smbclient -N -L //10.129.14.128

# 3) connect to an important share
smbclient //10.129.14.128/notes -N
smb: \> ls
smb: \> get filename.txt

# 4) faster tool for permissions
smbmap -H 10.129.14.128

# 5) extract usernames and domain information
rpcclient -U "" 10.129.14.128
rpcclient $> enumdomusers
rpcclient $> netshareenumall
rpcclient $> srvinfo

```

### Additional Information

- **enum4linux-ng**: a comprehensive tool that collects everything (shares, users, groups, policy) in one command: 
  ```
  enum4linux-ng -A 10.129.14.128

  ```
- **NetExec** (the official successor for  CrackMapExec): the modern standard tool for scanning SMB and testing credentials at scale: 
  ```
  netexec smb 10.129.14.128 -u users.txt -p passwords.txt

  ```
- **MS17-010 (EternalBlue)**: the most famous SMBv1 vulnerability, you can verify it with: 
  ```
  nmap --script smb-vuln-ms17-010 -p445 10.129.14.128

  ```

---

## NFS (Ports 111, 2049)

NFS = **Network File System**, a protocol that lets a machine open a folder on a server as if it were a local folder. similar to SMB but more common in the Linux/Unix world.

### Important Options

| Option Meaning      |                                                 |
| ------------------ | ----------------------------------------------- |
| `rw`               | read and write                                    |
| `ro`               | read only                                       |
| `sync`             | safer transfer but slower                           |
| `async`            | faster but less secure                             |
| `root_squash`      | prevents root on your machine from acting as root on the share |
| `no_root_squash`   | ⚠️ Dangerous: keeps root on your machine as root on the share     |
| `insecure`         | allows the use of ports above 1024                    |
| `no_subtree_check` | reduces subtree checking issues                 |

Most dangerous settings together: `rw` + `no_root_squash` + `insecure`.

### NFS scanning with Nmap

```
sudo nmap --script nfs* -sV -p111,2049 <IP>

```

Important scripts: `nfs-showmount` (available shares), `nfs-ls` (share contents), `nfs-statfs` (share space), `rpcinfo` (RPC services and ports).

### Manually listing NFS shares

```
showmount -e <IP>

```

Example output: `/mnt/nfs 10.129.14.0/24`

### Mounting the NFS Share

```
mkdir target-NFS
sudo mount -t nfs <IP>:/./target-NFS/ -o nolock
cd target-NFS
ls -la
tree.

```

### root\_squash vs no\_root\_squash

- **root\_squash**: If you are root on your machine, the server will not treat you as root (protection).
- **no\_root\_squash**: If you are root on your machine, the server will treat you as actual root. if this is present and you have write permission, you may be able to upload files with root privileges — a common privilege escalation technique.

### Unmounting

```
cd..
sudo umount./target-NFS

```

It is always important to unmount instead of leaving the share mounted.

### Practical Example

```
# 1) Scan
sudo nmap -sV -sC -p111,2049 10.129.14.128

# 2) list the  exports
showmount -e 10.129.14.128

# 3) do mount andEnumerate
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/./target-NFS/ -o nolock
cd target-NFS && ls -la

# 4) if there is no_root_squash + write access → privilege escalation
# (run these on your machine with root privileges)
cp /bin/bash./bash-suid
chmod +s./bash-suid
# when run the file from the target machine itself will run with root privileges

# 5) exit and cleanup
cd..
sudo umount./target-NFS

```

### Additional Information

- **NFSv3** (the most common for scanning) has no real authentication other than UID/GID, unlike **NFSv4** which supports Kerberos and better user mapping.
- if your UID on your machine matches the UID of a user with permissions on the share, you will be able to read their files even without root.

---

## DNS (Port 53)

DNS translates a domain name into an IP, and runs on TCP/UDP 53.

### Important DNS Records

| Record Function  |                                     |
| --------------- | ----------------------------------- |
| `A`             | IPv4 address                        |
| `AAAA`          | IPv6 address                        |
| `MX`            | Mail servers                        |
| `NS`            | Name servers                        |
| `TXT`           | text information (SPF, verification...) |
| `CNAME`         | Alias foranother name                      |
| `PTR`           | reverse lookup from IP to domain     |
| `SOA`           | DNS zone management information          |

### Dangerous Settings

| Option Description      |                                                                       |
| ----------------- | --------------------------------------------------------------------- |
| `allow-query`     | who is allowed to send queries to the server                                      |
| `allow-recursion` | who is allowed send recursive requests                                   |
| `allow-transfer`  | who is allowed get a zone transfer (AXFR) — if open to everyone, this is a major problem |
| `zone-statistics` | collect zone statistics                                              |

### Finding the DNS Server version

```
dig CH TXT version.bind @10.129.120.85

```

Example output: `"9.10.6-P1-Debian"` — useful for finding out whether there are known vulnerabilities for that version.

### Practical Example

```
# 1) Scan
sudo nmap -sV -sC -p53 10.129.14.128

# 2) Basic queries
dig ns domain.htb @10.129.14.128
dig any domain.htb @10.129.14.128

# 3) Try Zone Transfer (AXFR)
dig axfr domain.htb @10.129.14.128
dig axfr internal.domain.htb @10.129.14.128

# 4) if AXFR fails, try brute-forcing subdomains
dnsenum --dnsserver 10.129.14.128 --enum -f subdomains.txt domain.htb

```

### Additional Information

- Alternative tools: `fierce`, or `dnsrecon -d domain.htb -a` (automatically tries AXFR).
- if AXFR succeeds, it means `allow-transfer` is open to anyone — a serious finding that should be recorded in the report.

---

## SMTP (Ports 25, 587, 465)

the protocol responsible for sending emails.

| Port use  |                                                              |
| --------------- | ------------------------------------------------------------ |
| 25              | sending/relaying emails between servers (Server-to-Server)       |
| 587             | sending from an authenticated user (Client-to-Server), usually with STARTTLS |
| 465             | SMTP over SSL/TLS                                            |

STARTTLS starts the connection in plaintext and then switches it to encrypted.

### SMTP Commands

| Command | Function  |                                        |
| -------------- | -------------------------------------- |
| `HELO`         | start the session with the hostname                 |
| `EHLO`         | like HELO but shows ESMTP capabilities            |
| `AUTH PLAIN`   | login                             |
| `MAIL FROM`    | set the sender                           |
| `RCPT TO`      | set the recipient                          |
| `DATA`         | start writing the email content              |
| `RSET`         | cancel the current operation while keeping the connection |
| `VRFY`         | check whether the user exists               |
| `EXPN`         | check a mailbox/mailing list         |
| `NOOP`         | keep the connection alive                     |
| `QUIT`         | end the session                           |

### Dangerous Setting: Open Relay

the server allows anyone to use it to send emails anywhere. example of a dangerous configuration (Postfix):

```
mynetworks = 0.0.0.0/0

```

it means: allow any IP in the world to use the server as a relay → spam / mail spoofing / hiding the attack source.

### Footprinting with Nmap

```
sudo nmap 10.129.14.128 -sC -sV -p25

```

Example output:

```
25/tcp open smtp Postfix smtpd
smtp-commands: PIPELINING, SIZE, VRFY...

```

### Open Relay check

```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

```

if the result `Server is an open relay (16/16 tests)` there is a dangerous misconfiguration.

### Practical Example

```
# 1) Scan
sudo nmap 10.129.14.128 -sC -sV -p25

# 2) verify from Open Relay
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

# 3) manual enumeration (banner grabbing + VRFY)
nc -nv 10.129.14.128 25
> EHLO test
> VRFY root

# 4) enumerate users with a dedicated tool
smtp-user-enum -M VRFY -U users.txt -t 10.129.14.128

```

### Additional Information

- Nmap there is ready script for user enumeration: `--script smtp-enum-users`.
- if the mail server is connected to a web application, sometimes the email contents themselves leak information about the backend.

---

## IMAP and POP3

after SMTP sends the email, the user needs to read it from the server — this is where IMAP/POP3 comes in (receiving and reading, not sending).

| Protocol Port Secure Port  |     |             |
| ---------------------------- | --- | ----------- |
| POP3                         | 110 | 995 (POP3S) |
| IMAP                         | 143 | 993 (IMAPS) |

the letter `S` = Secure/SSL/TLS.

### Why is it important in security testing?

if you find credentials such as `robin:robin`, try them on IMAP/POP3. if they work, you can: see the folders, read the emails, find credentials/tokens inside messages, and collect usernames and internal domains.

### IMAP commands

| Command | Function    |                           |
| ---------------- | ------------------------- |
| `LOGIN`          | log in  Login              |
| `LIST "" *`      | list folders/mailboxes |
| `SELECT INBOX`   | select the inbox          |
| `FETCH <ID> all` | fetch a specific message           |
| `LOGOUT`         | exit                    |

### POP3 commands

| Command | Function  |                       |
| -------------- | --------------------- |
| `USER`         | enter username          |
| `PASS`         | enter password        |
| `STAT`         | number of messages           |
| `LIST`         | list messages and sizes  |
| `RETR id`      | read a message by ID |
| `DELE id`      | delete a message             |
| `CAPA`         | show capabilities  |
| `QUIT`         | exit                  |

### Practical Example

```
# Scan
sudo nmap -sV -sC -p110,143,993,995 10.129.14.128

# manual connection to POP3
nc -nv 10.129.14.128 110
> USER robin
> PASS robin
> LIST
> RETR 1

# manual connection to IMAP
nc -nv 10.129.14.128 143
> a1 LOGIN robin robin
> a2 LIST "" *
> a3 SELECT INBOX
> a4 FETCH 1 all

# for encrypted ports (993/995) use openssl
openssl s_client -connect 10.129.14.128:995 -crlf
openssl s_client -connect 10.129.14.128:993 -crlf

```

### Additional Information

- `curl` can interact directly with IMAP/POP3: 
  ```
  curl -k 'imaps://10.129.14.128' --user robin:robin

  ```

---

## SNMP (Ports 161, 162)

a protocol for managing and monitoring network devices (Routers, Switches, Servers, Printers, IoT).

- **Port 161/UDP**: the port where the Agent (the managed device) receives queries (queries/GET/SET) coming from the Manager.
- **Port 162/UDP**: the port where the Manager receives Traps — alerts automatically sent by the Agent to the Manager when a certain event happens.

if you find port **161/UDP open**, you should think about SNMP Enumeration, and start looking for **community string** — this is like a simple password, and the most common one:

```
public

```

### SNMP Versions

| Version Description  |                                                                      |
| ------------- | -------------------------------------------------------------------- |
| SNMPv1        | old and weak, no encryption and no real authentication                      |
| SNMPv2c       | still very common, also weak because the  community string is sent in plain text |
| SNMPv3        | the most secure — has username/password and encryption, but is more complex to configure            |

### MIB and OID

- **MIB**: like a "catalog" that tells you what information the device has that you can ask about.
- **OID**: the address of the information inside the device (Example: `.1.3.6.1.2.1` the beginning of any system information).

### Most dangerous misconfiguration

```
rwcommunity public

```

or

```
rwuser noauth

```

`rw` = read/write, meaning not only can you read, you can also change settings.

### tools SNMP

**1. snmpwalk** — the most important tool when you know the community string:

```
snmpwalk -v2c -c public 10.129.14.128

```

it may show you: OS version, hostname, contact email, location, running services, installed packages, network info, and sometimes users/processes.

**2. onesixtyone** — brute force for community strings:

```
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

```

Example output: `10.129.14.128 [public]`

**3. braa** — a fast tool performs brute force on values the OIDs in parallel (useful if you have the community string and you want to pull a large amount from the OIDs quickly, not specifically a tool for finding the “version”):

```
braa public@10.129.14.128:.1.3.6.*

```

### Practical Example

```
# 1) make sure the port is open
sudo nmap -sU -p161 10.129.14.128 --open

# 2) try a common community string
snmpwalk -v2c -c public 10.129.14.128

# 3) if public did not work, brute force
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

# 4) once you find the community string, do a full dump
snmpwalk -v2c -c <community> 10.129.14.128

# 5) quickly pull a set of OIDs in parallel
braa public@10.129.14.128:.1.3.6.*

# 6) pull the system name specifically (sysDescr, it usually contains OS/version details)
snmpwalk -v2c -c public 10.129.14.128 1.3.6.1.2.1.1.1.0

```

### Additional Information

- another useful tool: `snmp-check 10.129.14.128 -c public` produces a clean, easy-to-read report.
- ready-made Nmap scripts: 
  ```
  sudo nmap -sU -p161 --script snmp-info,snmp-processes,snmp-netstat 10.129.14.128

  ```

---

## MySQL (Port 3306)

MySQL stores website and application data (usernames, passwords, emails, posts, permissions...). if you can access it, you may find very sensitive information.

### Nmap Scan

```
sudo nmap -sV -sC -p3306 --script mysql* <IP>

```

it shows you: MySQL version, whether there are users without passwords, usernames, databases, authentication information, and sometimes credentials.

### Login

```
mysql -u root -h <IP>              # without a password
mysql -u root -p<PASSWORD> -h <IP> # with a password (with no space after -p)

```

### MySQL Commands

```
show databases;
use <database>;
show tables;
show columns from <table>;
select * from <table>;
select * from <table> where <column> = "value";

```

### Default Databases

| Database Description       |                                              |
| -------------------- | -------------------------------------------- |
| `information_schema` | metadata about databases, tables, and columns |
| `mysql`              | very important — contains users and privileges          |
| `performance_schema` | performance information                                 |
| `sys`                | system, performance, and host information         |

### Dangerous settings

- **user/password plain text** in config files — if you can read the server files, you may find credentials.
- **debug / sql\_warnings**: if enabled, they may produce error messages containing sensitive information (useful in SQL Injection).
- **secure\_file\_priv**: determines where MySQL can read/write files from — very important for exploitation.

### Important file locations

```
/etc/mysql/mysql.conf.d/mysqld.cnf   # configuration
/var/lib/mysql                        # data storage location

```

### if the connection is rejected because of an SSL certificate

```
ERROR 2026 (HY000): TLS/SSL error: self-signed certificate in certificate chain

```

solution:

```
mysql -u robin -probin -h 10.129.42.195 --ssl-verify-server-cert=FALSE

```

### Practical Example

```
# 1) Scan
sudo nmap -sV -sC -p3306 --script mysql* 10.129.14.128

# 2) try logging in without a password
mysql -u root -h 10.129.14.128

# 3) if you have a password
mysql -u root -pPASSWORD -h 10.129.14.128

# 4) enumeration
show databases;
use wordpress;
show tables;
select * from wp_users;

# 5) look for sensitive things: users, hashes, emails, tokens, config data

```

### Additional Information

- Brute force with Hydra if no known credentials: 
  ```
  hydra -L users.txt -P passwords.txt mysql://10.129.14.128

  ```
- if you have the `FILE` privilege and `secure_file_priv` is empty, you can read files from the server with  `LOAD_FILE()`, or even write a web shell with  `INTO OUTFILE` if the path is writable.

---

## MSSQL (Port 1433)

A database server from Microsoft, usually in Windows environments and.NET applications.

### MSSQL Tools

**1. Nmap**

```
sudo nmap -sV -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info,ms-sql-config <IP>

```

it shows you: hostname, domain/NetBIOS name, MSSQL version, instance name, there  there is empty password, there  named pipes enabled, NTLM information.

Example:

```
ServerName = SQL-01
InstanceName = MSSQLSERVER
Version = Microsoft SQL Server 2019
TCP port = 1433
Named pipe = \\SQL-01\pipe\sql\query

```

**2. Metasploit mssql\_ping**

```
msfconsole
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <IP>
run

```

**3. impacket-mssqlclient** — the most important tool if you have credentials:

```
impacket-mssqlclient Administrator@<IP> -windows-auth

```

### Commands after login

```
select name from sys.databases;

```

Default databases:

| Database Description  |                                                       |
| --------------- | ----------------------------------------------------- |
| `master`        | basic SQL Server system information                 |
| `model`         | template for any new database                               |
| `msdb`          | used by SQL Server Agent (jobs, alerts) — very useful |
| `tempdb`        | temporary data                                          |
| `resource`      | read-only, contains system objects                        |

### Most dangerous misconfigurations

1. **Weak/default** **`sa`** **credentials** — `sa` is the admin account.
2. **without encryption** — credentials/data can be captured.
3. **Self-signed certificates** — possible spoofing.
4. **Named Pipes enabled** — an additional connection method, useful for enumeration/lateral movement.
5. **`xp_cmdshell`** — if enabled and you have permissions, you can execute system commands from inside MSSQL. Nmap script: `ms-sql-xp-cmdshell`.
   
### Importance of MSSQL in Active Directory

in an AD environment, MSSQL can help with: privilege escalation, lateral movement, collecting domain info, Windows Authentication, and accessing other servers. do not treat it as just a database — consider it a possible path to another machine or higher privileges.

### Practical Example

```
# 1) full scan with the important scripts
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER \
  -sV -p1433 10.129.201.248

# 2) if you have credentials, log in
impacket-mssqlclient Administrator@10.129.201.248 -windows-auth

# 3) after logging in, enumerate
SQL> select name from sys.databases;
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');   -- is the current user a sysadmin?

# 4) if sysadmin, enable xp_cmdshell and execute system commands
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';

```

### Additional Information

- **Linked Servers**: if the server has a linked server to another server, you can use this to access other servers even if you do not have credentials for them directly (`EXEC ('query') AT [linked_server]`).

---

## Oracle TNS (Port 1521)

### important files

- **tnsnames.ora** (client-side): defines what the client connects to (Host, Port, Service Name, SID).
- **listener.ora** (server-side): defines which IP/port/services the listener will listen on.

### SID

**SID** = the name of the Oracle database instance. to connect you need: `IP + Port + SID/Service Name`, Example:

```
10.129.204.235:1521/XE

```

### Basic steps

```
# Scan
sudo nmap -p1521 -sV <IP> --open

# SID discovery
sudo nmap -p1521 -sV <IP> --open --script oracle-sid-brute

```

### ODAT (Oracle Database Attacking Tool)

a very powerful tool for Oracle enumeration — SIDs, usernames, passwords, misconfigurations, vulnerabilities, privileges:

```
./odat.py all -s <IP>

```

### Logging in with sqlplus

```
sqlplus <username>/<password>@<IP>/<SID>

```

Commands after login:

```
select table_name from all_tables;
select * from user_role_privs;   -- current user privileges

```

### sysdba

```
sqlplus scott/tiger@<IP>/XE as sysdba

```

if it succeeds, these are very high privileges (like DBA).

### Extracting Hashes

```
select name, password from sys.user$;

```

useful for cracking them offline.

### File Upload via ODAT

```
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s <IP> -d XE -U <username> -P <password> --sysdba \
  --putFile C:\\inetpub\\wwwroot testing.txt./testing.txt

```

Confirm the upload:

```
curl http://<IP>/testing.txt

```

Default web paths: Linux `/var/www/html`, Windows `C:\inetpub\wwwroot`.

### Practical Example

```
# 1) Scan
sudo nmap -p1521 -sV 10.129.14.128 --open

# 2) SID brute force
sudo nmap -p1521 -sV 10.129.14.128 --open --script oracle-sid-brute

# 3) full ODAT enumeration
./odat.py all -s 10.129.14.128

# 4) login after finding credentials
sqlplus scott/tiger@10.129.14.128/XE

# 5) enumeration
SQL> select table_name from all_tables;
SQL> select * from user_role_privs;

# 6) try sysdba
sqlplus scott/tiger@10.129.14.128/XE as sysdba

```

### Additional Informatio

- Common SIDs worth trying if brute force fails: `XE`, `ORCL`, `PROD`, `TEST`, `DEV`.
- another tool: `tnscmd10g version -h <IP>` to pull version information directly from the listener.

---

## IPMI (Port 623)

IPMI is not a normal service inside the operating system — it runs on a separate component called **BMC** (Baseboard Management Controller), and it works even if the server itself is powered off.

if you can access IPMI/BMC, it is like standing in front of the server yourself — meaning access can be approximately equal to **physical access** to the server.

### Common IPMI names

```
HP iLO
Dell iDRAC
Supermicro IPMI

```

### First step

```
sudo nmap -sU -p623 --script ipmi-version <IP>

```

if it shows `IPMI-2.0` then the service is present.

### Default Credentials

| Product Username / Password  |                                                                              |
| --------------------------- | ---------------------------------------------------------------------------- |
| Dell iDRAC                  | `root` / `calvin`                                                            |
| Supermicro IPMI             | `ADMIN` / `ADMIN`                                                            |
| HP iLO                      | `Administrator` / a random 8-character/alphanumeric password (usually written on the server itself) |

### Most dangerous point: IPMI 2.0 RAKP

in IPMI 2.0 there is an authentication issue called **RAKP**: the server can send you the hash of an existing user's password *before* you actually log in. so you can obtain the hash and crack it offline with Hashcat.

### Extracting Hashes with Metasploit

```
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <IP>
run

```

### Cracking the Hash with Hashcat

```
hashcat -m 7300 ipmi.txt wordlist.txt

```

if HP iLO has an 8-character password (digits + uppercase letters):

```
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u

```

### After cracking the password

try it on: IPMI web console, SSH, Telnet, other servers — because admins sometimes reuse the same password in more than one place.

### Practical Example

```
# 1) Scan
sudo nmap -sU -p623 --script ipmi-version 10.129.14.128

# 2) try default creds (such as root/calvin on iDRAC)

# 3) if that does not work, extract the hash
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS 10.129.14.128; run; exit"

# 4) crack the hash
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# 5) try the password on other services (SSH, web panel...)

```

---

## Linux Remote Management Protocols

### SSH (Port 22)

the secure way to access a Linux machine remotely.

**Uses**: Remote shell, File transfer (scp/sftp), Port forwarding/Tunneling, Running commands remotely.

**Versions**: SSH-1 (old and weak) versus SSH-2 (currently used and secure).

**Login methods**: Password Authentication (vulnerable to brute force if the password is weak) or Public Key Authentication (more secure).

#### Dangerous SSH settings

| Setting — Risk              |                                                  |
| ---------------------------- | ------------------------------------------------ |
| `PasswordAuthentication yes` | allows password login → vulnerable to brute force     |
| `PermitRootLogin yes`        | allows direct root login                           |
| `PermitEmptyPasswords yes`   | allows an empty password (a disaster)                        |
| `Protocol 1`                 | uses the old and weak SSH-1                      |
| `AllowTcpForwarding yes`     | allows port forwarding (may help with pivoting) |
| `X11Forwarding yes`          | allows X11 graphical interface forwarding                   |

configuration file: `/etc/ssh/sshd_config`

#### SSH Enumeration

```
nmap -sV -p22 <IP>

```

**ssh-audit** — checks SSH settings and cryptography:

```
ssh-audit <IP>

```

it shows you: SSH banner, OpenSSH version, supported algorithms, weak crypto, authentication methods.

#### Finding allowed login methods

```
ssh -v user@<IP>

```

if appears `publickey,password,keyboard-interactive` then server allows more than one login method.

#### Practical Example

```
# 1) Scan and version identification
nmap -sV -sC -p22 10.129.14.128

# 2) security audit of the settings
ssh-audit 10.129.14.128

# 3) check login methods
ssh -v testuser@10.129.14.128

# 4) if there is no rate limiting, try brute force (with extreme caution)
hydra -L users.txt -P passwords.txt ssh://10.129.14.128

```

#### Additional Information

- **CVE-2018-15473**: an old OpenSSH vulnerability that allows username enumeration through timing differences between the response for "a nonexistent user" and"an existing user with the wrong password".
- file transfer: `scp file.txt user@10.129.14.128:/tmp/` or `sftp user@10.129.14.128`.

---

### Rsync (Port 873)

a tool for transferring and synchronizing files — commonly used for Backups, File syncing, Mirroring.

**Why is it important in penetration testing?** sometimes Rsync is open without authentication → you can view/download server files, which can give you: config files, secrets, SSH keys, backup files, passwords, source code.

#### Rsync scanning and finding shares

```
nmap -sV -p873 <IP>

nc -nv <IP> 873
#list

```

#### List/download share contents

```
rsync -av --list-only rsync://<IP>/dev
rsync -av rsync://<IP>/dev.

```

if Rsync is running over SSH:

```
rsync -av -e ssh user@<IP>:/path.
rsync -av -e "ssh -p2222" user@<IP>:/path.   # if SSH is on a different port

```

#### Practical Example

```
# 1) Scan
nmap -sV -p873 10.129.14.128

# 2) list the available modules
nc -nv 10.129.14.128 873
#list

# 3) browse the contents of a specific module
rsync -av --list-only rsync://10.129.14.128/dev

# 4) download everything
rsync -av rsync://10.129.14.128/dev./loot/

```

---

### R-Services (Ports 512-514)

very old services that were used to access and control Unix/Linux remotely before SSH — unsafe because they send data without encryption.

| Port Service  |        |
| ------------ | ------ |
| 512/tcp      | rexec  |
| 513/tcp      | rlogin |
| 514/tcp      | rsh    |

**Commands**: `rlogin` (login to a remote machine), `rsh` (remote shell), `rexec` (execute commands remotely), `rcp` (copy files), `rwho` (who is logged in on the network), `rusers` (more information about connected users).

**Why are they dangerous?** they rely on trust files instead of passwords — if the machine sees you as "trusted", it may let you in without a password:

```
/etc/hosts.equiv   # global trust for all users
~/.rhosts           # trust specific to each user

```

The most dangerous thing in `.rhosts`: the `+` (wildcard). dangerous example: `+ +` it means allow almost anyone from anywhere.

#### Practical Example

```
# 1) Scan
sudo nmap -sV -p512,513,514 10.129.14.128

# 2) try rlogin without a password
rlogin 10.129.14.128 -l root
# if you get in without a password, there is a misconfiguration in.rhosts or hosts.equiv

# 3) collect information about connected users
rwho
rusers -al 10.129.14.128

```

---

## Windows Remote Management Protocols

### RDP (Port 3389)

accessing a Windows machine with a full GUI — like having the machine's screen open in front of you remotely.

#### Login from Linux

```
xfreerdp /u:<user> /p:'<password>' /v:<IP> /cert:ignore /dynamic-resolution

```

#### Enumeration

```
nmap -sV -sC -p3389 --script rdp* <IP>

```

it shows you: hostname, domain name, computer name, Windows version, NLA enabled or not, RDP encryption info, system time.

#### NLA (Network Level Authentication)

a protection that makes the user authenticate before a full RDP session is opened. if enabled, this is better for security. in Nmap can see `CredSSP (NLA): SUCCESS`.

#### Practical Example

```
# 1) Scan
nmap -sV -sC -p3389 --script rdp* 10.129.14.128

# 2) graphical login
xfreerdp /u:administrator /p:'Password123!' /v:10.129.14.128 /cert:ignore

```

#### Additional Information

- **CVE-2019-0708 (BlueKeep)**: a very famous RCE vulnerability in RDP on old Windows systems (7, Server 2008), which you can verify with Nmap scripts for RDP vulnerabilities.

---

### WinRM (Ports 5985, 5986)

Remote Management for Windows without a GUI — instead of opening the Desktop, you open a PowerShell remote shell. `5985` = HTTP, `5986` = HTTPS.

#### The most important tool: evil-winrm

```
evil-winrm -i <IP> -u <user> -p '<password>'

```

if it succeeds: `*Evil-WinRM* PS C:\Users\user\Documents>`

#### Scan

```
nmap -sV -sC -p5985,5986 <IP>

```

if you find `5985/tcp open http Microsoft HTTPAPI` then WinRM is present.

#### Practical Example

```
# 1) Scan
nmap -sV -sC -p5985,5986 10.129.14.128

# 2) login with evil-winrm
evil-winrm -i 10.129.14.128 -u administrator -p 'Password123!'

# 3) alternative with NetExec if you want to test credentials against more than one target
netexec winrm 10.129.14.128 -u administrator -p 'Password123!'

```

---

### WMI (Port 135)

a very powerful way to manage Windows remotely — execute commands, read system information, manage services, and work with Windows settings.

#### The most important tool

from Impacket:

```
wmiexec.py <user>:'<password>'@<IP> "hostname"

```

if it succeeds, executes the command and returns the result.

### Practical Example — Workflow with Windows protocols

```
# 1) scan all ports at once
nmap -sV -sC -p3389,5985,5986,135 10.129.14.128

# 2) if you find RDP
nmap -sV -sC -p3389 --script rdp* 10.129.14.128

# 3) if you have credentials
xfreerdp /u:<user> /p:'<password>' /v:<IP>

# 4) if you find WinRM
evil-winrm -i <IP> -u <user> -p '<password>'

# 5) if you want to try WMI
wmiexec.py <user>:'<password>'@<IP> "hostname"

```

---

## Quick Reference Cheat Sheet

| Service Port Main Tool Quick Command  |                    |                       |                                                |
| ------------------------------- | ------------------ | --------------------- | ---------------------------------------------- |
| FTP                             | 21/tcp             | nmap / ftp            | `nmap -sV -p21 -sC -A <IP>`                    |
| SMB                             | 139, 445/tcp       | smbclient / rpcclient | `smbclient -N -L //<IP>`                       |
| NFS                             | 111, 2049          | showmount             | `showmount -e <IP>`                            |
| DNS                             | 53                 | dig                   | `dig axfr domain.htb @<IP>`                    |
| SMTP                            | 25, 587, 465       | nmap                  | `nmap -p25 --script smtp-open-relay <IP>`      |
| IMAP/POP3                       | 143, 993, 110, 995 | nc / openssl          | `nc -nv <IP> 143`                              |
| SNMP                            | 161, 162/udp       | snmpwalk              | `snmpwalk -v2c -c public <IP>`                 |
| MySQL                           | 3306/tcp           | mysql client          | `mysql -u root -h <IP>`                        |
| MSSQL                           | 1433/tcp           | impacket-mssqlclient  | `impacket-mssqlclient user@<IP> -windows-auth` |
| Oracle TNS                      | 1521/tcp           | ODAT / sqlplus        | `./odat.py all -s <IP>`                        |
| IPMI                            | 623/udp            | metasploit / hashcat  | `use auxiliary/scanner/ipmi/ipmi_dumphashes`   |
| SSH                             | 22/tcp             | ssh-audit             | `ssh-audit <IP>`                               |
| Rsync                           | 873/tcp            | rsync                 | `rsync -av --list-only rsync://<IP>/share`     |
| R-Services                      | 512-514/tcp        | rlogin                | `rlogin <IP> -l <user>`                        |
| RDP                             | 3389/tcp           | xfreerdp              | `xfreerdp /u:<user> /p:'<pass>' /v:<IP>`       |
| WinRM                           | 5985, 5986/tcp     | evil-winrm            | `evil-winrm -i <IP> -u <user> -p '<pass>'`     |
| WMI                             | 135/tcp            | wmiexec.py            | `wmiexec.py user:pass@<IP> "hostname"`         |
