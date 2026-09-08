# SNMP Lab

A simple Docker setup featuring an SNMP Agent (`snmpd`) and a Zabbix NMS instance.

## Setup

Run the environment using Docker Compose:

```bash
docker compose up -d
```

## Usage

### Test SNMP Agent

Query the agent from host using SNMP utilities (`snmpget`, `snmpwalk`):

- **Get System Description:**
  ```bash
  snmpget -v2c -c public localhost 1.3.6.1.2.1.1.1.0
  ```

- **Walk System Tree:**
  ```bash
  snmpwalk -v2c -c public localhost 1.3.6.1.2.1.1
  ```

### Add SNMP Agent to Zabbix

1. Open `http://localhost:8888` (Login: `Admin` / `zabbix`).
2. Go to **Configuration** -> **Hosts** -> **Create host**.
3. Set **Host name**: `snmp-target`.
4. Add an **SNMP interface**:
   - Change **Connect to** from IP to **DNS**.
   - **DNS name:** `snmp-target`
   - **Port:** `161`
5. Attach a template (e.g., `Linux SNMP` or `Generic SNMP`).
6. Set macro `{$SNMP_COMMUNITY}` to `public` if required.

> Tip: Use the DNS name `snmp-target` instead of an IP address so Zabbix can resolve the container over the Docker network.

## Details

- **Config File:** `snmpd.conf`
- **RO Community:** `public`
- **RW Community:** `private`