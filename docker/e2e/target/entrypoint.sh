#!/bin/sh
hostname pwnagotchi-e2e 2>/dev/null || true
echo active > /var/lib/fakesvc/pwnagotchi.state
touch /root/.pwnagotchi-auto
python3 /opt/api.py &
(i=0; while true; do i=$((i+1)); case $((i%3)) in 0) l=INFO;; 1) l=WARNING;; 2) l=ERROR;; esac; echo "[$(date +%T)] [$l] tick $i" >> /var/log/pwnagotchi.log; sleep 0.3; done) &
exec /usr/sbin/sshd -D -e
