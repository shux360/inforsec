# Full Demo Guide

## Purpose

This guide is a presentation-ready runbook for demonstrating the complete project in the UI and terminal.

It covers:

- Happy path success
- 2FA token usage
- Identity binding and pinning behavior
- Replay protection
- Revocation
- Rate limiting
- What to say during each step

For concepts and O-RAN security reasoning, read [ORAN_INFOSEC_EXPLAINED.md](ORAN_INFOSEC_EXPLAINED.md).

## Prerequisites

- Node.js 20+
- OpenSSL available in PATH
- Repository opened at project root

## One-time setup

1. Install dependencies in project root:

```bash
npm install
```

2. Install UI dependencies:

```bash
cd ui
npm install
cd ..
```

3. Generate demo certificates and keys:

```bash
npm run pki
```

4. Confirm pinned sender identity in [certs/pins.json](../certs/pins.json).

Minimum expected sender in this demo:

```json
{
  "xapps": {
    "xapp-legitimate": {
      "tlsFingerprint": "<fingerprint>",
      "signingPublicKey": "certs/xapp-signing.public.pem"
    }
  }
}
```

Optional: add TOTP secret for stronger 2FA validation:

```json
{
  "xapps": {
    "xapp-legitimate": {
      "tlsFingerprint": "<fingerprint>",
      "signingPublicKey": "certs/xapp-signing.public.pem",
      "totpSecret": "JBSWY3DPEHPK3PXP"
    }
  }
}
```

## Start services

1. Terminal A, start server:

```bash
npm run server
```

Expected startup logs:

- demo HTTP endpoint listening on 8080
- listening on 127.0.0.1:9443 with TLS 1.3 mTLS

2. Terminal B, start UI:

```bash
cd ui
npm run dev
```

3. Open http://localhost:5173

## UI quick orientation

In [ui/src/App.jsx](../ui/src/App.jsx), the demo page has:

- Shared secret for demo
- Sender ID (must exist in pins.json)
- Current token and Refresh token
- STIX payload editor
- Build envelope (simulate)
- Demo server URL
- Send to demo server
- Last server response

Use these exact values for baseline success:

- Shared secret: JBSWY3DPEHPK3PXP
- Sender ID: xapp-legitimate
- Demo server URL: http://127.0.0.1:8080/demo/send

## Scenario 1: Baseline success (must pass)

Goal: prove end-to-end secure processing works.

Steps in UI:

1. Keep Shared secret as JBSWY3DPEHPK3PXP
2. Keep Sender ID as xapp-legitimate
3. Keep sample STIX payload unchanged
4. Click Refresh token
5. Click Build envelope (simulate)
6. Click Send to demo server

Expected UI response:

```json
{
  "sent": true,
  "serverResponse": {
    "status": "accepted",
    "bundleId": "bundle--1",
    "objectCount": 1,
    "signatureHash": "..."
  }
}
```

Expected server log:

- accepted pinned client xapp-legitimate
- accepted CTI payload bundle--1 from xapp-legitimate

What to say in demo:

- UI builds payload and token
- Server-side bridge signs envelope using private key
- Bridge sends message over real mTLS
- RIC verifies identity and envelope, then accepts

## Scenario 2: Identity mismatch rejection

Goal: show sender identity must match certificate pin mapping.

Steps in UI:

1. Change Sender ID to demo-xapp
2. Click Build envelope (simulate)
3. Click Send to demo server

Expected response:

```json
{
  "sent": true,
  "serverResponse": {
    "status": "rejected",
    "reason": "senderId does not match pinned certificate identity"
  }
}
```

What to say:

- Even with a valid TLS channel, logical sender binding is enforced
- This blocks impersonation by mismatched identity claims

## Scenario 3: Replay protection rejection

Goal: show nonce replay is blocked.

Steps:

1. Build one envelope in UI
2. Send once and observe accepted
3. Without rebuilding, send again immediately

Expected second response:

```json
{
  "sent": true,
  "serverResponse": {
    "status": "rejected",
    "reason": "nonce already seen"
  }
}
```

What to say:

- Same nonce means replay attempt
- Replay cache rejects duplicate message to prevent repeated action

## Scenario 4: Invalid 2FA token rejection

Prerequisite: totpSecret configured for xapp-legitimate in [certs/pins.json](../certs/pins.json).

Goal: show second factor enforcement.

Steps:

1. Set Shared secret in UI to a wrong value, for example AAAA
2. Click Refresh token
3. Build envelope and send

Expected response:

```json
{
  "sent": true,
  "serverResponse": {
    "status": "rejected",
    "reason": "invalid two-factor token"
  }
}
```

What to say:

- Certificate and sender match are not enough
- Token must also match server-side shared secret

## Scenario 5: Revocation rejection

Goal: show emergency kill-switch for compromised certs.

Steps:

1. Copy current fingerprint from [certs/pins.json](../certs/pins.json) for xapp-legitimate
2. Add that fingerprint to revokedFingerprints in [config/revoked.json](../config/revoked.json)
3. Wait about 5 to 6 seconds for revocation hot reload
4. Send a new envelope from UI

Expected response:

```json
{
  "sent": true,
  "serverResponse": {
    "status": "rejected",
    "reason": "client certificate fingerprint is revoked"
  }
}
```

Cleanup after demo:

- Remove fingerprint from revoked list and save file
- Wait 5 to 6 seconds and test again

What to say:

- No server restart required
- Revocation watcher applies policy quickly

## Scenario 6: Rate limiting rejection

Goal: show availability protection.

Method A, UI rapid click:

1. Build envelope once
2. Click Send repeatedly until rejection appears

Method B, script-based:

```bash
node scripts/e2e_manual.js
```

Expected rejection sample:

```json
{
  "status": "rejected",
  "reason": "rate limit exceeded",
  "retryAfter": 60
}
```

What to say:

- Per-identity quotas prevent one client from exhausting server resources

## Suggested demo order for viva

1. Baseline success
2. Identity mismatch
3. Replay rejection
4. Invalid 2FA token
5. Revocation
6. Rate limiting

This order starts with confidence and then shows progressive security controls.

## Troubleshooting checklist

If UI says Failed to fetch:

- Confirm server running on 8080
- Confirm URL is http://127.0.0.1:8080/demo/send
- Confirm browser request includes x-demo-api-key header

If sender mismatch appears unexpectedly:

- Confirm Sender ID in UI matches key in [certs/pins.json](../certs/pins.json)
- Confirm fingerprint for that sender matches certificate in use

If token shows error:

- Re-enter secret in valid Base32 format
- Use default JBSWY3DPEHPK3PXP
- Click Refresh token again

If revocation does not update immediately:

- Wait at least 5 seconds (hot-reload interval)
- Validate [config/revoked.json](../config/revoked.json) has valid JSON

## Security notes

- The demo bridge is local-only and intended for training, not production exposure.
- Private keys are read from disk for demonstration purposes.
- For production design, move signing keys to HSM or a secured signing service.
