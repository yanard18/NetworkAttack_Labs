# Nmap Network Scanning & Firewall Evasion Laboratory

Welcome to the **Nmap Network Scanning & Firewall Evasion Lab**. This hands-on laboratory environment is designed to help students, cybersecurity practitioners, and network administrators understand how Nmap scans operate at the packet level, how firewalls (stateful and stateless) process network traffic, how to enumerate firewall rulesets using specialized scan techniques, and how firewall configuration weaknesses can be exploited or remediated.

---

## Lab Architecture & Topology

The laboratory environment is built using Docker Compose with an isolated subnetwork structure:

```
[ Attacker (Kali) ] <---> [ red_net (10.10.10.0/24) ]
   10.10.10.10                    |
                                  | Interface 1: 10.10.10.254
                          [ Firewall (Alpine) ]
                                  | Interface 2: 10.10.20.254
                                  |
[ Target (Nginx) ]  <---> [ blue_net (10.10.20.0/24) ]
   10.10.20.20
```

### Components
1. **Attacker Container** (`10.10.10.10`): Kali Linux container equipped with `nmap`, `tcpdump`, and net tools.
2. **Firewall Container** (`10.10.10.254` / `10.10.20.254`): Alpine Linux container configured as a dual-homed router (`net.ipv4.ip_forward=1`) running `iptables`.
3. **Target Container** (`10.10.20.20`): Alpine container running an Nginx web server on TCP port 80 (plus standard system ports).

---

## Lab Setup & Initialization

### 1. Prerequisites
- Docker & Docker Compose installed on the host system.

### 2. Starting the Environment
From the lab root directory (where `docker-compose.yml` is located), run:

```bash
docker compose up -d
```

Verify that all three containers are running:
```bash
docker compose ps
```

### 3. Accessing the Containers
Open separate terminal tabs or windows for container interaction:

- **Attacker Console:**
  ```bash
  docker exec -it attacker bash
  # Or using Docker Compose:
  # docker compose exec attacker bash
  ```
- **Firewall Console:**
  ```bash
  docker exec -it firewall sh
  # Or using Docker Compose:
  # docker compose exec firewall sh
  ```
- **Target Console:**
  ```bash
  docker exec -it target sh
  # Or using Docker Compose:
  # docker compose exec target sh
  ```

### 4. Verifying Baseline Connectivity
From the `attacker` container, verify that routing through the firewall to the target is operational:
```bash
ping -c 3 10.10.20.20
```

---

## Firewall Configuration Guide (`iptables`)

All firewall rules are configured on the `firewall` container within the `FORWARD` chain of `iptables`.

### Basic `iptables` Commands Checklist
- **View current FORWARD rules with line numbers:**
  ```bash
  iptables -L FORWARD -v -n --line-numbers
  ```
- **Flush all rules in FORWARD chain:**
  ```bash
  iptables -F FORWARD
  ```
- **Set default policy for FORWARD chain:**
  ```bash
  iptables -P FORWARD ACCEPT
  # or
  iptables -P FORWARD DROP
  ```

---

### Scenario Configurations

#### Scenario A: DROP vs REJECT Behavior
Configure the firewall to silently drop packets on TCP port 80, but actively reject packets on TCP port 22.

```bash
# Flush existing rules
iptables -F FORWARD

# Drop HTTP packets (Port 80)
iptables -A FORWARD -p tcp --dport 80 -j DROP

# Reject SSH packets (Port 22) with ICMP port-unreachable
iptables -A FORWARD -p tcp --dport 22 -j REJECT --reject-with icmp-port-unreachable
```

#### Scenario B: Stateless Firewall Rules
A stateless firewall inspects packets individually without tracking connection state (`SYN`, `ACK`, `ESTABLISHED`).

```bash
iptables -F FORWARD
iptables -P FORWARD DROP

# Allow incoming TCP connection requests (SYN) to port 80
iptables -A FORWARD -p tcp -d 10.10.20.20 --dport 80 -j ACCEPT

# Allow return traffic (ACK/RST) from target back to attacker
iptables -A FORWARD -p tcp -s 10.10.20.20 -j ACCEPT
```

#### Scenario C: Stateful Firewall Rules (Recommended Security Posture)
A stateful firewall uses the Linux `conntrack` engine to track protocol sessions.

```bash
iptables -F FORWARD
iptables -P FORWARD DROP

# Allow ESTABLISHED and RELATED packets in both directions
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Selectively allow NEW TCP connections to Port 80 on target
iptables -A FORWARD -p tcp -d 10.10.20.20 --dport 80 -m state --state NEW -j ACCEPT
```

#### Scenario D: Weak Firewall Rule (Source Port Trusting)
A common misconfiguration where high-numbered or specific source ports (like DNS source port 53 or FTP-DATA port 20) are blindly trusted.

```bash
iptables -F FORWARD
iptables -P FORWARD DROP

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow TCP traffic if the source port is 53 (DNS)
iptables -A FORWARD -p tcp --sport 53 -j ACCEPT

# Allow HTTP traffic to target port 80
iptables -A FORWARD -p tcp -d 10.10.20.20 --dport 80 -j ACCEPT
```

---

## Lab Tasks & Questions

### Task 1: Baseline Scanning (No Firewall Rules)
**Firewall Setup:** Run `iptables -F FORWARD` and `iptables -P FORWARD ACCEPT` on the `firewall` container.

Run the following scans from the `attacker` container against target `10.10.20.20`:
1. TCP Connect Scan: `nmap -sT -p 22,80,443,8080 10.10.20.20`
2. TCP SYN (Stealth) Scan: `nmap -sS -p 22,80,443,8080 10.10.20.20`
3. UDP Scan: `nmap -sU -p 53,67,161 10.10.20.20`

#### Questions:
- **Q1.1:** What is the difference between `-sT` and `-sS` at the TCP handshake layer? Why does `-sS` require root privileges?
- **Q1.2:** What responses did Nmap receive for port 80 (open) vs port 443 (closed) during a SYN scan?

---

### Task 2: Enumerating Firewall Rulesets (Stateless vs Stateful)

#### Part A: TCP ACK Scanning (`-sA`)
Apply **Scenario B (Stateless)** on the firewall container. Run:
```bash
nmap -sA -p 22,80,443 10.10.20.20
```
Next, apply **Scenario C (Stateful)** on the firewall container. Run the same command again:
```bash
nmap -sA -p 22,80,443 10.10.20.20
```

#### Questions:
- **Q2.1:** What does an Nmap TCP ACK scan (`-sA`) actually determine? Does it tell you if a port is `open` or `closed`?
- **Q2.2:** What port states does Nmap report under the Stateless configuration versus the Stateful configuration when performing an ACK scan? Explain the reason for this difference.

#### Part B: Stealth / Exotic Flag Scans (NULL, FIN, Xmas)
Apply **Scenario B (Stateless)** firewall rules. From the attacker container, execute:
```bash
nmap -sN -p 22,80,443 10.10.20.20  # NULL Scan
nmap -sF -p 22,80,443 10.10.20.20  # FIN Scan
nmap -sX -p 22,80,443 10.10.20.20  # Xmas Scan
```

#### Questions:
- **Q2.3:** How do RFC 793 TCP compliance rules dictate how an operating system should respond to a NULL, FIN, or Xmas scan on an open port vs a closed port?
- **Q2.4:** Why might a stateful firewall or modern OS alter the expected RFC 793 behavior for NULL/FIN/Xmas scans?

---

### Task 3: Identifying DROP vs REJECT Filtering
Apply **Scenario A (DROP vs REJECT)** on the firewall container.

From the attacker, run:
```bash
nmap -sS -p 22,80 -packet-trace 10.10.20.20
```
*(Optional: Run `tcpdump -nn -i eth0 tcp` on the attacker container in a separate window to inspect raw packets).*

#### Questions:
- **Q3.1:** Compare the Nmap scan duration and status output for Port 80 (DROP) vs Port 22 (REJECT).
- **Q3.2:** What specific ICMP or TCP control packets were returned by the firewall for Port 22 versus Port 80?
- **Q3.3:** From a defensive engineering perspective, what are the pros and cons of choosing `DROP` over `REJECT` for firewall rules?

---

### Task 4: Firewall Evasion & Bypass Techniques

#### Part A: Source Port Spoofing / Manipulation
Apply **Scenario D (Weak Firewall Rule - Source Port 53 Trusted)** on the firewall container.

First, test standard SYN scan on closed/filtered ports (e.g. port 22):
```bash
nmap -sS -p 22 10.10.20.20
```
Now, manipulate the source port using Nmap's `-g` / `--source-port` parameter:
```bash
nmap -sS -g 53 -p 22 10.10.20.20
```

#### Questions:
- **Q4.1:** Did setting `--source-port 53` bypass the firewall restriction on port 22? Explain why this misconfiguration occurs in legacy firewall implementations.
- **Q4.2:** How can firewall administrators configure `iptables` state tracking (`-m state --state NEW,ESTABLISHED`) to prevent source-port spoofing attacks?

#### Part B: Packet Fragmentation
Apply a rule on the firewall that inspects and drops TCP packets matching standard HTTP headers or payloads, or a basic stateless packet filter blocking TCP SYN packets to port 80.

From the attacker container, execute a fragmented SYN scan:
```bash
nmap -sS -f --mtu 16 -p 80 10.10.20.20
```

#### Questions:
- **Q4.3:** How does packet fragmentation (`-f` or `--mtu`) attempt to evade simple network intrusion detection systems (NIDS) and stateless packet filters?
- **Q4.4:** What features of modern stateful firewalls (e.g., IP defragmentation reassembly) neutralize packet fragmentation evasion?

#### Part C: Decoy Scanning & Obfuscation
From the attacker container, run a scan using decoy IP addresses:
```bash
nmap -sS -D 10.10.10.5,10.10.10.6,ME,10.10.10.7 -p 80 10.10.20.20
```
While running this scan, inspect incoming packets on the target or firewall container using `tcpdump`:
```bash
tcpdump -i any host 10.10.20.20 -n
```

#### Questions:
- **Q4.5:** What is the purpose of decoy scanning (`-D`)? Does decoy scanning hide the attacker's true IP from receiving the final response if the port is open?
- **Q4.6:** How can network security analysts differentiate between decoy scan packets and the legitimate scanner IP when reviewing packet captures?

---

## Answers & Reference Guide

<details>
<summary>Click to reveal expected answers and technical explanations</summary>

### Task 1 Key
- **Q1.1:** `-sT` completes the full 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`), establishing a full OS connection. `-sS` sends a `SYN`, waits for `SYN-ACK`, and immediately sends a `RST` to tear down the connection before it completes. Root privileges are required for `-sS` because raw socket creation is required to forge craft raw TCP packets.
- **Q1.2:** Open port (80) replies with `SYN-ACK`. Closed port (443) replies with `RST-ACK`.

### Task 2 Key
- **Q2.1:** An ACK scan (`-sA`) checks whether ports are **Filtered** or **Unfiltered**. It cannot determine if a port is Open or Closed because an `ACK` packet sent to an unfiltered port (whether open or closed) triggers a `RST` response from the host operating system.
- **Q2.2:** 
  - **Stateless rule set:** ACK scan returns `UNFILTERED` for ports allowed through the firewall (since the firewall passes the ACK, and the target host returns RST).
  - **Stateful rule set:** ACK scan returns `FILTERED` for all ports because the firewall drops unexpected ACK packets that do not belong to an existing entry in the `conntrack` table.
- **Q2.3:** RFC 793 specifies that if a port is closed, an incoming NULL, FIN, or Xmas packet must trigger a `RST`. If the port is open, the packet should be silently discarded.
- **Q2.4:** Microsoft Windows and some middleboxes do not strictly comply with RFC 793, sending `RST` responses regardless of port state, or stateful firewalls drop non-SYN initial packets regardless of target port state.

### Task 3 Key
- **Q3.1:** `DROP` results in Nmap waiting for timeouts, leading to longer scan durations and reporting `filtered`. `REJECT` yields an instant response, reporting `closed` or `filtered` (depending on the ICMP message type returned).
- **Q3.2:** `REJECT` returns an `ICMP Port Unreachable` (Type 3, Code 3) packet or a `TCP RST` packet. `DROP` returns nothing.
- **Q3.3:** `DROP` slows down automated attacker recon scans and conserves outbound bandwidth. However, `REJECT` is often preferred internally for troubleshooting network errors cleanly without causing long application connection timeouts.

### Task 4 Key
- **Q4.1:** Yes, if the firewall rule naively checks `--sport 53` without checking connection state (`--state ESTABLISHED`), any SYN packet originating from port 53 bypasses the rule.
- **Q4.2:** By enforcing stateful inspection (`-m state --state ESTABLISHED,RELATED`), the firewall ensures that incoming packets with source port 53 are only allowed if they are responses to active DNS requests initiated from inside the network.
- **Q4.3:** Fragmentation splits the TCP header across multiple IP fragments. Simple packet filters that only inspect the first fragment or lack fragment reassembly engines fail to match header fields (like destination port or TCP flags).
- **Q4.4:** Connection tracking and IP reassembly modules (`nf_defrag_ipv4`) reassemble fragments before applying firewall rules.
- **Q4.5:** Decoy scanning mixes spoofed scan traffic with the attacker's real IP to obscure the attacker's true identity in target logs. However, the attacker must still send packets from their real IP to receive SYN-ACK responses.
- **Q4.6:** Analysts can look for MAC address consistency (if on the same local subnet), TTL variances, TCP window size patterns, or routing paths that mismatch spoofed IPs.

</details>

---

## Cleanup Instructions

To stop and remove all containers, networks, and resources created by this lab, run:

```bash
docker compose down
```

---
*Created for educational network security training. Use responsibly in authorized laboratory environments only.*
