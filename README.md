# Pwnagotchi Manager

A small PyQt app to manage **your own** Pwnagotchi over SSH for:
- status info (uptime/disk/ip)
- service control (start/stop/restart/status)
- logs
- config edit with backup
- upload/download files via SFTP
- reboot/shutdown

This project intentionally does **not** provide features for offensive actions.

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
