# AWS Deployment Guide

Target VM: `54.242.77.97`, 2 vCPU, 8 GB RAM.

## Security Group

Recommended inbound rules:

| Port | Source | Purpose |
| --- | --- | --- |
| TCP 22 | Your admin IP only | SSH |
| TCP 9443 | Your demo/client IP only | RIC secure CTI listener |

Avoid opening TCP `9443` to `0.0.0.0/0` unless the demonstration specifically requires it.

## Install Runtime

On the VM:

```bash
sudo apt update
sudo apt install -y git openssl
node --version
openssl version
```

Install Node.js 20 or newer if the VM does not already have it.

## Copy Project

Use either `git clone` or `scp` from your development machine. Example:

```bash
scp -r ./inforsec ubuntu@54.242.77.97:~/oran-cti-secure
ssh ubuntu@54.242.77.97
cd ~/oran-cti-secure
```

## Generate Certificates

The default RIC certificate SAN includes `127.0.0.1` and `54.242.77.97`.

```bash
node scripts/generate-pki.js
```

If the VM gets a new IP or DNS name:

```bash
RIC_CERT_IPS=127.0.0.1,NEW_PUBLIC_IP RIC_CERT_DNS=localhost,public-dns-name node scripts/generate-pki.js
```

## Start RIC Server

```bash
RIC_HOST=0.0.0.0 RIC_PORT=9443 node src/ric-server.js
```

Expected:

```text
[RIC] listening on 0.0.0.0:9443 with TLS 1.3 mTLS
```

## Run xApp Client

From the same VM:

```bash
node src/xapp-client.js --host 127.0.0.1 --port 9443 --profile xapp --mode normal
```

From a separate client machine, copy these files securely first:

```text
certs/ca.cert.pem
certs/xapp.cert.pem
certs/xapp.key.pem
certs/xapp-signing.key.pem
samples/stix-threat-indicator.json
```

Then run:

```bash
node src/xapp-client.js --host 54.242.77.97 --port 9443 --profile xapp --mode normal
```

## systemd Service

Create `/etc/systemd/system/oran-cti-ric.service`:

```ini
[Unit]
Description=O-RAN CTI Near-RT RIC Secure Receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/ubuntu/oran-cti-secure
Environment=RIC_HOST=0.0.0.0
Environment=RIC_PORT=9443
ExecStart=/usr/bin/node /home/ubuntu/oran-cti-secure/src/ric-server.js
Restart=on-failure
RestartSec=3
User=ubuntu

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now oran-cti-ric
sudo systemctl status oran-cti-ric
```

View logs:

```bash
journalctl -u oran-cti-ric -f
tail -f logs/audit.log
```

## Production Hardening Notes

- Keep private keys out of git and restrict permissions with `chmod 600 certs/*.key.pem`.
- Replace demo CA with the organisation PKI or a managed private CA.
- Use CRL/OCSP or a managed revocation workflow instead of only `config/revoked.json`.
- Restrict Security Group sources to known xApp/demo IPs.
- Rotate certificates and signing keys before real use.
- Use CloudWatch or another central log sink for `logs/audit.log`.
