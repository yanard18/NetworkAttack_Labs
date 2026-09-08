# FTP Server and Attacks Learning Lab

Welcome to the FTP Learning & Security Lab. This environment uses Docker and vsftpd to test File Transfer Protocol (FTP) operations, raw protocol commands, active vs. passive modes, security misconfigurations, and defensive countermeasures.

---

## Getting Started

### 1. Start the Lab Container
```bash
docker compose up -d --build
```

### 2. Verify Container Status
```bash
docker compose ps
```

### 3. Stop the Lab
```bash
docker compose down
```

---

## Lab Accounts & Configuration

| Account Type | Username | Password | Base Directory | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Anonymous** | `anonymous` / `ftp` | *(none / any)* | `/var/ftp/anon` | Read `/pub`, Write `/incoming` |
| **Standard User** | `ftpuser` | `password123` | `/home/ftpuser` | Read / Write in home |
| **Admin User** | `admin` | `adminpass` | `/home/admin` | Read / Write in home |

---

## Network & Ports

* **TCP Port 21**: FTP Control Channel (receives commands like `USER`, `PASS`, `LIST`, `RETR`)
* **TCP Port 20**: FTP Active Data Channel
* **TCP Ports 30000–30009**: FTP Passive Data Range (`PASV_ADDRESS=127.0.0.1`)

---

## Core FTP Concepts

FTP uses two separate TCP connections:
1. **Control Connection (Port 21)**: Transmits commands and server responses.
2. **Data Connection**: Transmits directory listings and file content.

### Active vs. Passive Mode
* **Active Mode (`PORT`)**: Client listens on a dynamic port and sends `PORT` command. Server connects back from port 20. (Fails behind NAT/firewalls).
* **Passive Mode (`PASV`)**: Client sends `PASV` command. Server opens a passive port (30000–30009) and client connects to it. Run `passive` in the `ftp` CLI before listing files.

---

## Hands-On Exercises

### Exercise 1: Anonymous Access
```bash
curl -s ftp://127.0.0.1/pub/welcome_notice.txt
```

Interactive `ftp` client:
```text
ftp 127.0.0.1
Name: anonymous
Password: (press Enter)
ftp> passive
ftp> ls /pub
ftp> get /pub/welcome_notice.txt -
ftp> quit
```

### Exercise 2: Anonymous File Upload
```bash
echo "Test file payload" > /tmp/payload.txt
curl -s -T /tmp/payload.txt ftp://127.0.0.1/incoming/payload.txt
curl -s ftp://127.0.0.1/incoming/payload.txt
```

### Exercise 3: Authenticated File Access
```bash
curl -s -u ftpuser:password123 ftp://127.0.0.1/confidential_report.txt
curl -s -u admin:adminpass ftp://127.0.0.1/admin_notes.txt
```

### Exercise 4: Cleartext Traffic Sniffing
```bash
sudo tcpdump -i lo port 21 -A
```

### Exercise 5: Inspect Audit Logs
```bash
docker exec -it ftp-lab-server tail -f /var/log/vsftpd.log
```

---

## Hydra Brute-Force Commands

Hydra automates dictionary password attacks over network protocols by issuing rapid `USER` and `PASS` sequences.

### Single User Attack
```bash
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://127.0.0.1
```

### Multi-User and Custom Password List Attack
```bash
hydra -L users.txt -P passwords.txt -t 4 -V ftp://127.0.0.1
```

**Common Flags:**
* `-l <user>`: Single target username
* `-L <file>`: File containing candidate usernames
* `-p <pass>`: Single candidate password
* `-P <file>`: File containing candidate passwords (wordlist)
* `-t <tasks>`: Number of parallel connections (default is 16)
* `-V`: Verbose display showing each attempt

---

## Suggested Wordlists

Common dictionary wordlists for authentication testing:

* **RockYou Wordlist**: `/usr/share/wordlists/rockyou.txt` (Standard on Kali Linux / SecLists)
* **SecLists Passwords**:
  * Default Credentials: `SecLists/Usernames/top-usernames-shortlist.txt`
  * Common Passwords: `SecLists/Passwords/Common-Credentials/10k-most-common.txt`
* **Custom Python Lab Script**: Included in lab as `brute_force_lab.py`
  ```bash
  python3 brute_force_lab.py
  ```

---

## Defensive Countermeasures

1. **Authentication Rate-Limiting & IP Banning:**
   * Deploy Fail2ban to monitor log files (`/var/log/vsftpd.log`) for repeated `530 Login incorrect` failures and dynamically block source IPs via iptables/nftables.

2. **Account Lockout Policy:**
   * Configure PAM authentication modules to lock user accounts temporarily after multiple failed login attempts.

3. **Disable Anonymous Write Access:**
   * In `vsftpd.conf`, set `anon_upload_enable=NO` and `anon_mkdir_write_enable=NO` to prevent arbitrary file uploads.

4. **Protocol Migration (SFTP / FTPS):**
   * Replace unencrypted FTP with **SFTP** (SSH File Transfer Protocol) or **FTPS** (FTP over TLS) to encrypt control commands and transferred data.

5. **Strong Password & Access Control:**
   * Enforce high-entropy passwords and restrict local user logins using `chroot_local_user=YES` and `userlist_enable=YES`.

---

## Configuration Files

* `vsftpd.conf` - [file:///home/mek/Documents/FTP_Lab/vsftpd.conf](file:///home/mek/Documents/FTP_Lab/vsftpd.conf)
* `entrypoint.sh` - [file:///home/mek/Documents/FTP_Lab/entrypoint.sh](file:///home/mek/Documents/FTP_Lab/entrypoint.sh)
* `Dockerfile` - [file:///home/mek/Documents/FTP_Lab/Dockerfile](file:///home/mek/Documents/FTP_Lab/Dockerfile)
* `docker-compose.yml` - [file:///home/mek/Documents/FTP_Lab/docker-compose.yml](file:///home/mek/Documents/FTP_Lab/docker-compose.yml)
* `brute_force_lab.py` - [file:///home/mek/Documents/FTP_Lab/brute_force_lab.py](file:///home/mek/Documents/FTP_Lab/brute_force_lab.py)
