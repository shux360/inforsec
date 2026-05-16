# Security Design

## Scenario

The Near-RT RIC receives CTI telemetry from xApps or external CTI feeds. The xApp is treated as untrusted until it proves identity with a certificate, matches a pinned fingerprint, and sends a signed encrypted payload.

## Protocol Flow

1. RIC starts a TLS 1.3 server and requests a client certificate.
2. xApp connects with its client certificate and validates the RIC certificate against the demo CA.
3. RIC validates the xApp certificate against the demo CA.
4. RIC checks the xApp certificate fingerprint against `certs/pins.json`.
5. Both sides derive two session-bound keys using TLS exporter labels:
   - `oran-cti-payload-key-v1` for AES-256-GCM
   - `oran-cti-header-mac-key-v1` for HMAC-SHA256
6. xApp signs canonical JSON containing sender ID, nonce, timestamp, and STIX payload with ECDSA P-256.
7. xApp encrypts canonical STIX JSON with AES-256-GCM using the nonce as the 96-bit IV and the protected header as AAD.
8. RIC checks HMAC, timestamp, nonce uniqueness, AES-GCM tag, and ECDSA signature.
9. Accepted and rejected events are written to `logs/audit.log`.

## Security Property Mapping

| Property | Mechanism | Why it fits O-RAN CTI |
| --- | --- | --- |
| Confidentiality | TLS 1.3 and AES-256-GCM payload encryption | Threat telemetry may reveal attacker indicators and RAN policy decisions |
| Integrity | AES-GCM tag and HMAC-SHA256 header MAC | Detects ciphertext and metadata tampering |
| Authentication | CA validation plus xApp certificate pinning | Blocks unknown or incorrectly issued xApp identities |
| Non-repudiation | ECDSA P-256 signature over payload plus sender/timestamp/nonce | The xApp cannot later deny the submitted CTI record |
| Availability | Rate limiting per certificate fingerprint | Limits flooding by a compromised or noisy xApp |
| Replay resistance | 96-bit nonce, timestamp window, replay cache | Blocks duplicate telemetry injection |
| Forward secrecy | TLS 1.3 ECDHE and exporter-derived keys | Later key compromise does not expose previous sessions |

## Threat Model

| Threat | STRIDE | Demo | Mitigation |
| --- | --- | --- | --- |
| Rogue xApp injection | Spoofing | `demo:rogue` | CA validation plus certificate pinning |
| Self-signed foreign xApp | Spoofing | `demo:foreign` | Trusted CA verification |
| MITM reading or changing CTI | Information disclosure, tampering | Wireshark/TLS capture, `demo:tamper` | TLS 1.3, AES-GCM, HMAC |
| False telemetry or CTI poisoning | Tampering, repudiation | `demo:legit` plus signature checks | ECDSA payload signatures |
| Replay attack | Tampering | `demo:replay` | Nonce cache and timestamp window |
| Telemetry flooding | Denial of service | `demo:flood` | Per-certificate rate limiting |
| xApp key compromise | Elevation of privilege | Discuss in viva | Revocation config plus forward secrecy for past sessions |

## Changes From The Original Plan

The project keeps the original security goals but changes the implementation stack:

- Node.js replaces Python because Node.js and OpenSSL are available in the workspace without installing dependencies.
- TLS certificates use RSA-3072 for compatibility across Windows, Node, OpenSSL, and AWS.
- ECDSA P-256 is still used for payload signatures and non-repudiation.
- TLS exporter-derived keys replace any static shared AES/HMAC key.
- The Windows local demo uses TLS over named pipes to avoid local antivirus TLS interception; AWS deployment uses TCP.

## Files That Enforce Security

- `src/ric-server.js`: mTLS handling, certificate validation, pinning, replay, rate limiting, audit logging
- `src/xapp-client.js`: xApp certificate use, RIC certificate validation, attack modes
- `src/lib/envelope.js`: AES-GCM encryption/decryption, ECDSA sign/verify, HMAC, timestamp/nonce checks
- `scripts/generate-pki.js`: demo CA, certificates, pins, and ECDSA signing keys
- `config/revoked.json`: simple certificate fingerprint revocation list
