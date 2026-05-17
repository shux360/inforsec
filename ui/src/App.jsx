import * as React from "react";

const { useEffect, useState } = React;

const SECURITY_SECRET = "JBSWY3DPEHPK3PXP";
const TOTP_WINDOW_SECONDS = 30;
const AUDIT_LIMIT = 16;
const FLOOD_COUNT = 8;

const DEFAULT_PAYLOAD = {
  id: "bundle--soc-telemetry-001",
  type: "bundle",
  spec_version: "2.1",
  objects: [
    {
      type: "indicator",
      id: "indicator--soc-demo-001",
      name: "O-RAN CTI telemetry sample",
      pattern_type: "stix",
      pattern: "[network-traffic:dst_ref.value = '198.51.100.23']",
    },
  ],
};

function snapshotSecurityToken() {
  const token = "loading...";
  const elapsedSeconds = Math.floor(Date.now() / 1000) % TOTP_WINDOW_SECONDS;
  const secondsRemaining = TOTP_WINDOW_SECONDS - elapsedSeconds;
  const progress =
    (TOTP_WINDOW_SECONDS - secondsRemaining) / TOTP_WINDOW_SECONDS;

  return {
    token,
    secondsRemaining,
    progress,
    refreshedAt: new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
  };
}

function parsePayload(text) {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("payload JSON is empty");
  }
  return JSON.parse(trimmed);
}

function normalizeResponse(json, fallbackStatus) {
  const serverResponse = json?.serverResponse ?? json ?? null;
  const status =
    serverResponse?.status ??
    (fallbackStatus >= 200 && fallbackStatus < 300 ? "accepted" : "rejected");
  return {
    status,
    reason: serverResponse?.reason ?? null,
    signatureHash: serverResponse?.signatureHash ?? null,
    bundleId: serverResponse?.bundleId ?? null,
    objectCount: serverResponse?.objectCount ?? null,
    retryAfter: serverResponse?.retryAfter ?? null,
    sent: Boolean(json?.sent),
    raw: json,
  };
}

function buildTelemetryPayload(payloadText, token) {
  return {
    ...parsePayload(payloadText),
    twoFactor: { token },
  };
}

function buildSendRequestBody(senderId, nonce, payload, profile) {
  return {
    senderId,
    profile,
    nonce,
    payload,
  };
}

function buildCorruptedEnvelopeBody(senderId, nonce, payload, profile) {
  return {
    profile,
    senderId,
    nonce,
    payload,
    version: "1.0",
    timestamp: Math.floor(Date.now() / 1000),
    algorithms: {
      payload: "AES-256-GCM",
      signature: "ECDSA-P256-SHA256",
      headerMac: "HMAC-SHA256",
    },
    signature: "tampered-signature",
    ciphertext: "tampered-ciphertext",
    tag: "tampered-tag",
    headerMac: "tampered-header-mac",
  };
}

function getEnvelopeEndpoint(baseUrl) {
  try {
    const url = new URL(baseUrl);
    url.pathname = url.pathname.replace(/\/demo\/send\/?$/, "/demo/envelope");
    if (!url.pathname.endsWith("/demo/envelope")) {
      url.pathname = "/demo/envelope";
    }
    return url.toString();
  } catch {
    return String(baseUrl).replace(/\/demo\/send\/?$/, "/demo/envelope");
  }
}

export default function App() {
  const [senderId, setSenderId] = useState("xapp-legitimate");
  const [profile, setProfile] = useState("xapp");
  const [serverUrl, setServerUrl] = useState(
    import.meta.env.VITE_DEMO_SERVER_URL ?? "http://127.0.0.1:8080/demo/send",
  );
  const apiKey = import.meta.env.VITE_DEMO_API_KEY ?? "inforsec-demo-key";
  const [payloadText, setPayloadText] = useState(
    JSON.stringify(DEFAULT_PAYLOAD, null, 2),
  );
  const [security, setSecurity] = useState(() => snapshotSecurityToken());
  const [authenticatorInstance, setAuthenticatorInstance] = useState(null);
  const [lastResponse, setLastResponse] = useState(null);
  const [auditTrail, setAuditTrail] = useState([]);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const loadAuthenticator = async () => {
      const bufferModule = await import("@otplib/preset-browser/buffer.js");
      globalThis.buffer = bufferModule.default ?? bufferModule;
      const presetModule = await import("@otplib/preset-browser");
      if (!cancelled) {
        setAuthenticatorInstance(() => presetModule.authenticator);
      }
    };

    void loadAuthenticator().catch((error) => {
      if (!cancelled) {
        setLastResponse({ status: "rejected", reason: error.message });
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!authenticatorInstance) {
      return undefined;
    }

    const refresh = () => {
      const token = authenticatorInstance.generate(SECURITY_SECRET);
      const elapsedSeconds =
        Math.floor(Date.now() / 1000) % TOTP_WINDOW_SECONDS;
      const secondsRemaining = TOTP_WINDOW_SECONDS - elapsedSeconds;
      const progress =
        (TOTP_WINDOW_SECONDS - secondsRemaining) / TOTP_WINDOW_SECONDS;

      setSecurity({
        token,
        secondsRemaining,
        progress,
        refreshedAt: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      });
    };

    refresh();
    const intervalId = setInterval(refresh, 1000);
    return () => clearInterval(intervalId);
  }, [authenticatorInstance]);

  const pushAuditEvent = (entry) => {
    setAuditTrail((current) => [entry, ...current].slice(0, AUDIT_LIMIT));
  };

  const submitBridgeBody = async ({ label, tone, token, endpoint, body }) => {
    setIsSending(true);
    try {
      const response = await fetch(endpoint ?? serverUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-demo-api-key": apiKey,
        },
        body: JSON.stringify(body),
      });

      const json = await response.json().catch(() => null);
      const normalized = normalizeResponse(json, response.status);
      setLastResponse(normalized);
      pushAuditEvent({
        label,
        tone: normalized.status === "accepted" ? tone : "critical",
        token,
        at: new Date().toLocaleTimeString(),
        response: normalized,
      });
      return normalized;
    } catch (error) {
      const failure = { status: "rejected", reason: error.message };
      setLastResponse(failure);
      pushAuditEvent({
        label,
        tone: "critical",
        token,
        at: new Date().toLocaleTimeString(),
        response: failure,
      });
      return failure;
    } finally {
      setIsSending(false);
    }
  };

  const submitTelemetry = async ({ label, token, tone }) => {
    try {
      const payload = buildTelemetryPayload(payloadText, token);
      return await submitBridgeBody({
        label,
        tone,
        token,
        body: buildSendRequestBody(
          senderId,
          `soc-${tone}-${Date.now()}`,
          payload,
          profile,
        ),
      });
    } catch (error) {
      const failure = { status: "rejected", reason: error.message };
      setLastResponse(failure);
      pushAuditEvent({
        label,
        tone: "critical",
        token,
        at: new Date().toLocaleTimeString(),
        response: failure,
      });
      return failure;
    }
  };

  const submitReplaySimulation = async () => {
    let payload;
    try {
      payload = buildTelemetryPayload(payloadText, security.token);
    } catch (error) {
      const failure = { status: "rejected", reason: error.message };
      setLastResponse(failure);
      pushAuditEvent({
        label: "Replay Attack Simulation",
        tone: "critical",
        token: security.token,
        at: new Date().toLocaleTimeString(),
        response: failure,
      });
      return;
    }

    const nonce = `soc-replay-${Date.now()}`;
    const body = buildSendRequestBody(senderId, nonce, payload, profile);
    const first = await submitBridgeBody({
      label: "Replay Attack Simulation - First Transmission",
      tone: "legit",
      token: security.token,
      body,
    });

    await submitBridgeBody({
      label: "Replay Attack Simulation - Replay Frame",
      tone: first.status === "accepted" ? "critical" : "critical",
      token: security.token,
      body,
    });
  };

  const submitFloodSimulation = async () => {
    let payload;
    try {
      payload = buildTelemetryPayload(payloadText, security.token);
    } catch (error) {
      const failure = { status: "rejected", reason: error.message };
      setLastResponse(failure);
      pushAuditEvent({
        label: "Availability/Flood Simulation",
        tone: "critical",
        token: security.token,
        at: new Date().toLocaleTimeString(),
        response: failure,
      });
      return;
    }

    for (let index = 0; index < FLOOD_COUNT; index += 1) {
      const body = buildSendRequestBody(
        senderId,
        `soc-flood-${Date.now()}-${index}`,
        payload,
        profile,
      );
      await submitBridgeBody({
        label: `Availability/Flood Simulation #${index + 1}`,
        tone: "legit",
        token: security.token,
        body,
      });
    }
  };

  const submitTamperSimulation = async () => {
    let payload;
    try {
      payload = buildTelemetryPayload(payloadText, security.token);
    } catch (error) {
      const failure = { status: "rejected", reason: error.message };
      setLastResponse(failure);
      pushAuditEvent({
        label: "Ciphertext Tamper Simulation",
        tone: "critical",
        token: security.token,
        at: new Date().toLocaleTimeString(),
        response: failure,
      });
      return;
    }

    const body = buildCorruptedEnvelopeBody(
      senderId,
      `soc-tamper-${Date.now()}`,
      payload,
      profile,
    );

    await submitBridgeBody({
      label: "Ciphertext Tamper Simulation",
      tone: "critical",
      token: security.token,
      endpoint: getEnvelopeEndpoint(serverUrl),
      body,
    });
  };

  const accepted = lastResponse?.status === "accepted";
  const rejected = lastResponse?.status === "rejected";
  const responseReason = lastResponse?.reason ?? null;
  const authReady = Boolean(authenticatorInstance);

  return (
    <div className="soc-shell">
      <header className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Open RAN CTI Security Operations</p>
          <h1>mTLS-secured telemetry with live 2FA verification</h1>
          <p className="hero-description">
            Drive the demo bridge with a valid rotating TOTP token, or
            deliberately spoof identity to observe the Near-RT RIC rejection
            path in real time.
          </p>
        </div>
        <div className="hero-meta">
          <div className="meta-card">
            <span className="meta-label">API key</span>
            <strong>{apiKey}</strong>
          </div>
          <div className="meta-card">
            <span className="meta-label">Bridge URL</span>
            <strong>{serverUrl}</strong>
          </div>
        </div>
      </header>

      <main className="dashboard-grid">
        <section className="panel security-panel">
          <div className="panel-head">
            <div>
              <p className="panel-kicker">Security Module</p>
              <h2>Live TOTP authenticator</h2>
            </div>
            <span className="security-chip">30-second window</span>
          </div>

          <div
            className="totp-ring"
            style={{ "--ring-progress": security.progress }}
          >
            <div className="totp-ring-inner">
              <span className="totp-label">Current token</span>
              <strong className="totp-token">{security.token}</strong>
              <span className="totp-subtitle">
                Refreshes at {security.refreshedAt}
              </span>
            </div>
          </div>

          <div className="totp-strip">
            <div>
              <span className="metric-label">Time left</span>
              <strong>{security.secondsRemaining}s</strong>
            </div>
            <div className="progress-track" aria-hidden="true">
              <span
                className="progress-fill"
                style={{
                  width: `${(security.secondsRemaining / TOTP_WINDOW_SECONDS) * 100}%`,
                }}
              />
            </div>
          </div>
        </section>

        <section className="panel command-panel">
          <div className="panel-head">
            <div>
              <p className="panel-kicker">Telemetry Controls</p>
              <h2>Attack simulation console</h2>
            </div>
            <span className="security-chip security-chip--neutral">
              xapp-legitimate
            </span>
          </div>

          <label className="field">
            <span>Sender ID</span>
            <select
              value={profile}
              onChange={(event) => {
                const p = event.target.value;
                setProfile(p);
                // set sensible default senderId for profile but allow manual override
                const defaults = {
                  xapp: "xapp-legitimate",
                  rogue: "xapp-rogue",
                  foreign: "xapp-foreign-self-signed",
                };
                setSenderId(defaults[p] ?? senderId);
              }}
            >
              <option value="xapp">xApp (legitimate)</option>
              <option value="rogue">Rogue (unpinned)</option>
              <option value="foreign">Foreign (self-signed)</option>
            </select>

            <input
              value={senderId}
              onChange={(event) => setSenderId(event.target.value)}
            />
          </label>

          <label className="field">
            <span>Demo bridge URL</span>
            <input
              value={serverUrl}
              onChange={(event) => setServerUrl(event.target.value)}
            />
          </label>

          <label className="field">
            <span>Telemetry payload</span>
            <textarea
              rows={12}
              value={payloadText}
              onChange={(event) => setPayloadText(event.target.value)}
            />
          </label>

          <div className="command-row">
            <button
              className="primary-button"
              type="button"
              onClick={() =>
                void submitTelemetry({
                  label: "Send Legitimate Telemetry",
                  token: security.token,
                  tone: "legit",
                })
              }
              disabled={isSending || !authReady}
            >
              Send Legitimate Telemetry
            </button>
            <button
              className="secondary-button danger"
              type="button"
              onClick={() =>
                void submitTelemetry({
                  label: "Simulate Identity Spoofing (Invalid TOTP)",
                  token: "000000",
                  tone: "spoof",
                })
              }
              disabled={isSending || !authReady}
            >
              Simulate Identity Spoofing (Invalid TOTP)
            </button>
          </div>

          <div className="command-row command-row--secondary">
            <button
              className="secondary-button"
              type="button"
              onClick={() => void submitReplaySimulation()}
              disabled={isSending || !authReady}
            >
              Replay Attack Simulation
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => void submitFloodSimulation()}
              disabled={isSending || !authReady}
            >
              Availability/Flood Simulation
            </button>
          </div>

          <div className="command-row command-row--single">
            <button
              className="secondary-button"
              type="button"
              onClick={() => void submitTamperSimulation()}
              disabled={isSending || !authReady}
            >
              Ciphertext Tamper Simulation
            </button>
          </div>

          <p className="supporting-copy">
            Each request attaches the current six-digit TOTP to the JSON payload
            before it reaches the HTTP bridge.
          </p>

          <div
            className="network-note"
            title="Rogue CA and Foreign Certificate (mTLS) attempts are blocked before the L7 bridge receives traffic."
          >
            <span className="network-note__label">Network security note</span>
            <p>
              Rogue CA and Foreign Certificate (mTLS) intrusion attempts are
              dropped at the L4 Network Edge by the Near-RT RIC and do not reach
              this L7 Management Console.
            </p>
          </div>
        </section>

        <section className="panel audit-panel">
          <div className="panel-head">
            <div>
              <p className="panel-kicker">Audit Log Visualizer</p>
              <h2>RIC response monitor</h2>
            </div>
            {accepted ? (
              <span
                key={lastResponse?.signatureHash ?? "accepted"}
                className="status-badge status-badge--accepted"
              >
                2FA Cryptographically Verified
              </span>
            ) : (
              <span
                className={`status-badge ${rejected ? "status-badge--rejected" : "status-badge--idle"}`}
              >
                {rejected
                  ? "Rejected"
                  : isSending
                    ? "Transmitting"
                    : "Awaiting response"}
              </span>
            )}
          </div>

          <div
            className={`response-card ${accepted ? "response-card--accepted" : rejected ? "response-card--rejected" : ""}`}
          >
            <div className="response-grid">
              <div>
                <span className="metric-label">Status</span>
                <strong>{lastResponse?.status ?? "idle"}</strong>
              </div>
              <div>
                <span className="metric-label">Signature hash</span>
                <strong>{lastResponse?.signatureHash ?? "pending"}</strong>
              </div>
              <div>
                <span className="metric-label">Bundle ID</span>
                <strong>{lastResponse?.bundleId ?? "pending"}</strong>
              </div>
              <div>
                <span className="metric-label">Object count</span>
                <strong>{lastResponse?.objectCount ?? "pending"}</strong>
              </div>
            </div>

            {rejected ? (
              <div className="rejection-block">
                <span className="metric-label">Reason</span>
                <strong>{responseReason ?? "unknown rejection reason"}</strong>
              </div>
            ) : null}
          </div>

          <div className="audit-list">
            {auditTrail.length > 0 ? (
              auditTrail.map((entry, index) => (
                <article
                  key={`${entry.at}-${index}`}
                  className={`audit-entry audit-entry--${entry.tone}`}
                >
                  <div className="audit-entry-head">
                    <strong>{entry.label}</strong>
                    <span>{entry.at}</span>
                  </div>
                  <div className="audit-entry-body">
                    <span>{entry.response?.status ?? "unknown"}</span>
                    {entry.response?.signatureHash ? (
                      <span>{entry.response.signatureHash}</span>
                    ) : null}
                    {entry.response?.reason ? (
                      <span className="audit-reason">
                        {entry.response.reason}
                      </span>
                    ) : null}
                  </div>
                </article>
              ))
            ) : (
              <div className="audit-placeholder">
                Send a legitimate or spoofed telemetry frame to populate the
                audit trail.
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
