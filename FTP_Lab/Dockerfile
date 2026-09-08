FROM alpine:3.19

RUN apk add --no-cache vsftpd shadow

# Create pam.d file for vsftpd authentication
RUN mkdir -p /etc/pam.d && \
    echo "auth required pam_unix.so nullok" > /etc/pam.d/vsftpd && \
    echo "account required pam_unix.so" >> /etc/pam.d/vsftpd && \
    echo "session required pam_unix.so" >> /etc/pam.d/vsftpd

# Create ftp user directory if missing
RUN mkdir -p /var/ftp/anon

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 21 20 30000-30009

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
