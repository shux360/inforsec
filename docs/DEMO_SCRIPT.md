# Live Demonstration Script

Target time: 8 to 10 minutes.

## Preparation

```bash
node scripts/generate-pki.js
node --test
```

Expected: all unit tests pass.

## One-Command Demo

```bash
node src/demo-runner.js all
```

On Windows, this uses TLS over named pipes for the local demo. On Linux/AWS, run the manual TCP flow below.

## Step 1: Legitimate Flow

Command:

```bash
node src/demo-runner.js legit
```

Show:

- TLS 1.3 cipher: `TLS_AES_256_GCM_SHA384`
- RIC accepts pinned xApp certificate
- RIC accepts STIX bundle
- Audit log records sender identity and signature hash

Security properties: confidentiality, integrity, authentication, non-repudiation.

## Step 2: Rogue xApp

Command:

```bash
node src/demo-runner.js rogue
```

Expected:

```text
certificate not in pinned xApp set
```

Explain: the rogue certificate is signed by the same CA, but it is not pinned by the RIC, so CA validity alone is not enough.

## Step 3: Self-Signed xApp

Command:

```bash
node src/demo-runner.js foreign
```

Expected:

```text
certificate issuer does not match trusted CA
```

Explain: unauthorised external CTI feeds cannot join the E2 trust domain.

## Step 4: Tampered Payload

Command:

```bash
node src/demo-runner.js tamper
```

Expected:

```text
Unsupported state or unable to authenticate data
```

Explain: one ciphertext byte is flipped after encryption. AES-GCM authentication detects the change before the RIC can process false telemetry.

## Step 5: Replay Attack

Command:

```bash
node src/demo-runner.js replay
```

Expected:

```text
accepted, rejected
nonce already seen
```

Explain: the first valid telemetry message is accepted; the duplicate is rejected by nonce replay detection.

## Step 6: Availability Control

Command:

```bash
node src/demo-runner.js flood
```

Expected: first messages are accepted, later messages are rejected with:

```text
rate limit exceeded
```

Explain: rate limiting is tied to the verified certificate fingerprint, not an unauthenticated IP string.

## Manual TCP Demo For AWS

On the VM:

```bash
RIC_HOST=0.0.0.0 RIC_PORT=9443 node src/ric-server.js
```

From the xApp host:

```bash
node src/xapp-client.js --host 54.242.77.97 --port 9443 --profile xapp --mode normal
node src/xapp-client.js --host 54.242.77.97 --port 9443 --profile rogue --mode normal
node src/xapp-client.js --host 54.242.77.97 --port 9443 --profile xapp --mode tamper
node src/xapp-client.js --host 54.242.77.97 --port 9443 --profile xapp --mode replay
```

## Viva Talking Points

- Why mTLS: both the RIC and xApp must prove identity.
- Why pinning: a CA-signed rogue xApp is still rejected.
- Why AES-GCM: confidentiality plus authenticated encryption without CBC padding risks.
- Why ECDSA: smaller signatures and strong non-repudiation.
- Why TLS exporter keys: no static AES key is stored or transmitted.
- Why nonce plus timestamp: prevents replay and stale telemetry.
- Why rate limiting by certificate fingerprint: availability control follows authenticated identity.
