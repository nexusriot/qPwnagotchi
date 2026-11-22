# Fake Pwnagotchi: sshd + sudo + stub systemctl/reboot/vcgencmd + REST API.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server openssh-sftp-server sudo python3 procps iproute2 tar gzip \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd

RUN useradd -m -s /bin/bash pi && echo 'pi:raspberry' | chpasswd \
    && echo 'pi ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/pi && chmod 0440 /etc/sudoers.d/pi \
    && mkdir -p /etc/pwnagotchi /root/handshakes /var/lib/fakesvc \
        /usr/local/share/pwnagotchi/availaible-plugins /usr/local/share/pwnagotchi/custom-plugins \
    && for p in grid gps webcfg; do echo "# $p" > /usr/local/share/pwnagotchi/availaible-plugins/$p.py; done \
    && echo "# mine" > /usr/local/share/pwnagotchi/custom-plugins/myplug.py \
    && echo "# init" > /usr/local/share/pwnagotchi/availaible-plugins/__init__.py \
    && for i in 1 2 3; do touch /root/handshakes/net$i.pcap; done && touch /root/handshakes/readme.txt \
    && printf 'Nov 21 pwnagotchi: hello from fake log\n' > /var/log/pwnagotchi.log \
    && echo pwnagotchi-e2e > /etc/hostname

COPY config.toml /etc/pwnagotchi/config.toml
RUN mkdir -p /opt/pristine && cp /etc/pwnagotchi/config.toml /opt/pristine/config.toml
COPY stubs/ /usr/local/bin/
COPY api.py entrypoint.sh /opt/
RUN chmod +x /usr/local/bin/* /opt/entrypoint.sh && chmod 0644 /etc/pwnagotchi/config.toml
EXPOSE 22 8080
ENTRYPOINT ["/opt/entrypoint.sh"]
