#!/bin/sh
set -e

# Create local FTP users if they don't exist
if ! id "ftpuser" >/dev/null 2>&1; then
    adduser -D -h /home/ftpuser -s /bin/false ftpuser
    echo "ftpuser:password123" | chpasswd
fi

if ! id "admin" >/dev/null 2>&1; then
    adduser -D -h /home/admin -s /bin/false admin
    echo "admin:adminpass" | chpasswd
fi

# Ensure anonymous FTP directory structure exists with valid chroot permissions
mkdir -p /var/ftp/anon/pub /var/ftp/anon/incoming
chown root:root /var/ftp/anon
chmod 755 /var/ftp/anon
chown -R ftp:ftp /var/ftp/anon/pub /var/ftp/anon/incoming
chmod 755 /var/ftp/anon/pub
chmod 777 /var/ftp/anon/incoming

# Add initial lab files if not present
if [ ! -f /var/ftp/anon/pub/welcome_notice.txt ]; then
    cat << 'EOF' > /var/ftp/anon/pub/welcome_notice.txt
===================================================
Welcome to the FTP Lab Public Server!
===================================================
This directory contains public resources.
Anonymous users can view files in /pub and upload files into /incoming.

Happy learning!
EOF
fi

if [ ! -f /home/ftpuser/confidential_report.txt ]; then
    cat << 'EOF' > /home/ftpuser/confidential_report.txt
CONFIDENTIAL COMPANY REPORT
---------------------------
Project Alpha Status: IN PROGRESS
Server Credentials Key: secret-token-99482
Internal IP: 10.0.4.15
EOF
    chown -R ftpuser:ftpuser /home/ftpuser
    chmod 755 /home/ftpuser
fi

if [ ! -f /home/admin/admin_notes.txt ]; then
    cat << 'EOF' > /home/admin/admin_notes.txt
ADMINISTRATOR SYSTEM NOTES
--------------------------
1. Update SSL/TLS certificates for FTPS next sprint.
2. Disable anonymous write access in production!
3. Review audit logs in /var/log/vsftpd.log periodically.
EOF
    chown -R admin:admin /home/admin
    chmod 755 /home/admin
fi

# Ensure log directory and file exist
mkdir -p /var/log
touch /var/log/vsftpd.log
chmod 644 /var/log/vsftpd.log

# Override PASV_ADDRESS environment variable if provided
if [ -n "$PASV_ADDRESS" ]; then
    sed -i "s/^pasv_address=.*/pasv_address=$PASV_ADDRESS/" /etc/vsftpd/vsftpd.conf
fi

echo "Starting vsftpd server..."
exec /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
