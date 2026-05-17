import * as React from "react";
import { canonicalJson } from "./lib/canonical-json";
const { useState, useEffect } = React;

function base32ToBytes(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = String(secret || "")
    .toUpperCase()
    .replace(/=+$/g, "")
    .replace(/\s+/g, "");

  let bits = "";
  for (const ch of normalized) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) {
      throw new Error("invalid base32 secret");
    }
    bits += idx.toString(2).padStart(5, "0");
  }

  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(out);
}

async function generateTotp(secret) {
  try {
    if (!globalThis.crypto?.subtle) {
      throw new Error("WebCrypto is not available");
    }

    const keyBytes = base32ToBytes(secret);
    const counter = Math.floor(Date.now() / 1000 / 30);
    const msg = new ArrayBuffer(8);
    const view = new DataView(msg);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"],
    );

    const signature = new Uint8Array(
      await globalThis.crypto.subtle.sign("HMAC", cryptoKey, msg),
    );
    const offset = signature[signature.length - 1] & 0x0f;
    const binary =
      ((signature[offset] & 0x7f) << 24) |
      ((signature[offset + 1] & 0xff) << 16) |
      ((signature[offset + 2] & 0xff) << 8) |
      (signature[offset + 3] & 0xff);

    return String(binary % 1000000).padStart(6, "0");
  } catch (e) {
    console.error("TOTP generation error:", e);
    return "error";
  }
}

export default function App() {
  const [secret, setSecret] = useState("JBSWY3DPEHPK3PXP");
  const [senderId, setSenderId] = useState("xapp-legitimate");
  const [stix, setStix] = useState(
    JSON.stringify(
      { id: "bundle--1", objects: [{ type: "indicator" }] },
      null,
      2,
    ),
  );
  const [token, setToken] = useState("");
  const [envelope, setEnvelope] = useState(null);
  const [serverUrl, setServerUrl] = useState("http://127.0.0.1:8080/demo/send");
  const [lastResponse, setLastResponse] = useState(null);

  const refreshToken = async () => {
    const newToken = await generateTotp(secret);
    setToken(newToken);
    return newToken;
  };

  // Generate initial TOTP token on mount and every 30 seconds
  useEffect(() => {
    void refreshToken();
    const interval = setInterval(() => {
      void refreshToken();
    }, 30000);
    return () => clearInterval(interval);
  }, [secret]);

  const makeEnvelope = async () => {
    const payload = JSON.parse(stix);
    const twoFactorToken = await generateTotp(secret);
    payload.twoFactor = { token: twoFactorToken };
    const payloadCanonical = canonicalJson(payload);
    const env = {
      senderId,
      timestamp: Math.floor(Date.now() / 1000),
      nonce: `demo-${Date.now()}`,
      payload: payload,
      signature: "SIMULATED_SIGNATURE",
    };
    setToken(twoFactorToken);
    setEnvelope({ env, payloadCanonical });
  };

  const sendEnvelope = async () => {
    if (!envelope) return;
    try {
      const resp = await fetch(serverUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-demo-api-key": "inforsec-demo-key",
        },
        body: JSON.stringify(envelope.env),
      });
      const json = await resp.json();
      setLastResponse(json);
    } catch (err) {
      setLastResponse({ error: err.message });
    }
  };

  return (
    <div className="app">
      <h1>Inforsec Demo UI</h1>
      <section>
        <h2>2FA (TOTP)</h2>
        <label>Shared secret for demo</label>
        <input value={secret} onChange={(e) => setSecret(e.target.value)} />
        <label>Sender ID (must exist in pins.json)</label>
        <input value={senderId} onChange={(e) => setSenderId(e.target.value)} />
        <div>
          Current token: <strong>{token}</strong>
        </div>
        <button onClick={() => void refreshToken()}>Refresh token</button>
      </section>

      <section>
        <h2>Sample STIX Payload</h2>
        <textarea
          rows={8}
          value={stix}
          onChange={(e) => setStix(e.target.value)}
        />
        <button onClick={() => void makeEnvelope()}>
          Build envelope (simulate)
        </button>
      </section>

      <section>
        <h2>Envelope</h2>
        <pre>
          {envelope
            ? JSON.stringify(envelope, null, 2)
            : "No envelope built yet"}
        </pre>
        <label>Demo server URL</label>
        <input
          value={serverUrl}
          onChange={(e) => setServerUrl(e.target.value)}
        />
        <div style={{ marginTop: 8 }}>
          <button onClick={sendEnvelope} disabled={!envelope}>
            Send to demo server
          </button>
        </div>
        <h3>Last server response</h3>
        <pre>
          {lastResponse ? JSON.stringify(lastResponse, null, 2) : "none"}
        </pre>
      </section>
    </div>
  );
}
