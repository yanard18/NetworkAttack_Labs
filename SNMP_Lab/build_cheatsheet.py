#!/usr/bin/env python3
import subprocess
import os

TITLE = "SNMP ENUMERATION & ATTACK CHEATSHEET"
OUTPUT_PDF = "cheatsheet.pdf"

DATA_SECTIONS = [
    {
        "title": "1. COMMUNITY STRING DISCOVERY & ENUMERATION",
        "items": [
            ("onesixtyone -c dict.txt 10.0.0.1", "Brute-force community strings across target host"),
            ("onesixtyone -c dict.txt -i hosts.txt", "Fast multi-host community string discovery"),
            ("snmp-check 10.0.0.1 -c public", "Automated system details & config enumeration"),
            ("hydra -P dict.txt 10.0.0.1 snmp", "SNMP community string brute-force with Hydra"),
        ]
    },
    {
        "title": "2. STANDARD SNMP COMMANDS (NET-SNMP)",
        "items": [
            ("snmpwalk -v2c -c public 10.0.0.1", "Walk full OID tree using SNMPv2c protocol"),
            ("snmpwalk -v2c -c public 10.0.0.1 .1", "Walk root OID tree starting from top level"),
            ("snmpget -v2c -c public 10.0.0.1 .1.3.6...", "Retrieve value for a specific exact OID"),
            ("snmpbulkwalk -v2c -c public 10.0.0.1", "High-speed bulk retrieval of large OID trees"),
            ("snmpset -v2c -c private 10.0.0.1 OID s val", "Write/modify value on a writable SNMP OID"),
        ]
    },
    {
        "title": "3. HIGH-SPEED MASS QUERYING (BRAA)",
        "items": [
            ("braa public@10.0.0.1:.1.3.6.1.2.1.1.*", "Query all System OIDs on target IP rapidly"),
            ("braa public@10.0.0.0/24:.1.3.6.1.2.1.1.1.0", "Query single OID (sysDescr) across /24 subnet"),
            ("braa private@10.0.0.1:.1.3.6.1.2...=s'val'", "Ultra-fast SNMP set request via braa"),
        ]
    },
    {
        "title": "4. NMAP SNMP AUTOMATION SCRIPTS",
        "items": [
            ("nmap -sU -p 161 --script snmp-brute target", "Discover valid community strings via Nmap"),
            ("nmap -sU -p 161 --script snmp-info target", "Extract basic system information & uptime"),
            ("nmap -sU -p 161 --script snmp-processes target", "Enumerate running processes via SNMP"),
            ("nmap -sU -p 161 --script snmp-interfaces target", "List network interface cards & IP configs"),
            ("nmap -sU -p 161 --script snmp-win32-users target", "Enumerate Windows domain/local user accounts"),
        ]
    },
    {
        "title": "5. CRITICAL RECONNAISSANCE OID BRANCHES",
        "items": [
            ("1.3.6.1.2.1.1 (sysDescr, sysName, uptime)", "System hardware, OS version, and uptime"),
            ("1.3.6.1.2.1.2 (ifDescr, ifPhysAddress)", "Network interfaces, MACs & IP configuration"),
            ("1.3.6.1.2.1.25.1 / 1.3.6.1.2.1.25.2", "System performance, RAM & storage metrics"),
            ("1.3.6.1.2.1.25.4.2.1.2 (hrSWRunName)", "Running system processes and executable paths"),
            ("1.3.6.1.2.1.25.6.3.1.2 (hrSWInstalledName)", "Installed software packages and patches"),
            ("1.3.6.1.4.1.77.1.2.25 (User Accounts)", "Windows local and domain user account list"),
        ]
    }
]

def generate_postscript():
    ps = []
    ps.append("%!PS-Adobe-3.0")
    ps.append("%%Title: " + TITLE)
    ps.append("%%Pages: 1")
    ps.append("/margin 40 def /pageheight 792 def /pagewidth 612 def")
    ps.append("/ypos pageheight margin sub def")
    
    ps.append("""
/drawHeader {
    gsave
    0.1 0.2 0.4 setrgbcolor
    margin ypos 15 sub pagewidth margin 2 mul sub 30 rectfill
    1 setgray
    /Helvetica-Bold findfont 14 scalefont setfont
    margin 10 add ypos 6 sub moveto
    (TITLE_PLACEHOLDER) show
    grestore
    /ypos ypos 45 sub def
} def

/drawSection {
    /stitle exch def
    gsave
    0.2 0.3 0.5 setrgbcolor
    /Helvetica-Bold findfont 11 scalefont setfont
    margin ypos 5 sub moveto
    stitle show
    margin ypos 7 sub moveto
    pagewidth margin sub ypos 7 sub lineto
    1 setlinewidth stroke
    grestore
    /ypos ypos 20 sub def
} def

/drawRow {
    /col2 exch def
    /col1 exch def
    /ypos ypos 14 sub def
    gsave
    /Courier-Bold findfont 9 scalefont setfont
    0 0 0 setrgbcolor
    margin ypos moveto
    col1 show
    
    /Helvetica findfont 9 scalefont setfont
    0.2 0.2 0.2 setrgbcolor
    margin 260 add ypos moveto
    col2 show
    grestore
} def
""".replace("TITLE_PLACEHOLDER", TITLE))

    ps.append("%%Page: 1 1")
    ps.append("drawHeader")

    for sec in DATA_SECTIONS:
        ps.append(f"({sec['title']}) drawSection")
        for cmd, desc in sec["items"]:
            cmd_esc = cmd.replace("(", "\\(").replace(")", "\\)")
            desc_esc = desc.replace("(", "\\(").replace(")", "\\)")
            ps.append(f"({cmd_esc}) ({desc_esc}) drawRow")
        ps.append("/ypos ypos 10 sub def")

    ps.append("showpage\n%%EOF")
    return "\n".join(ps)

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ps_file = os.path.join(script_dir, "temp_cheatsheet.ps")
    pdf_file = os.path.join(script_dir, OUTPUT_PDF)
    
    with open(ps_file, "w") as f:
        f.write(generate_postscript())
    
    cmd = f"ps2pdf {ps_file} {pdf_file}"
    subprocess.run(cmd, shell=True, check=True)
    if os.path.exists(ps_file):
        os.remove(ps_file)
    print(f"Successfully compiled PDF: {pdf_file}")

if __name__ == "__main__":
    main()
