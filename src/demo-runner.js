import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { defaultPaths } from './config.js';
import { startRicServer } from './ric-server.js';
import { runXapp } from './xapp-client.js';

const scenarios = {
  legit: {
    title: 'Baseline legitimate CTI flow',
    profile: 'xapp',
    mode: 'normal',
    expected: 'accepted'
  },
  rogue: {
    title: 'CA-signed but unpinned rogue xApp rejection',
    profile: 'rogue',
    mode: 'normal',
    expected: 'rejected'
  },
  foreign: {
    title: 'Self-signed foreign xApp TLS rejection',
    profile: 'foreign',
    mode: 'normal',
    expected: 'rejected'
  },
  tamper: {
    title: 'Ciphertext tamper detection',
    profile: 'xapp',
    mode: 'tamper',
    expected: 'rejected'
  },
  replay: {
    title: 'Replay attack rejection',
    profile: 'xapp',
    mode: 'replay',
    expected: 'mixed'
  },
  flood: {
    title: 'Availability control through per-certificate rate limiting',
    profile: 'xapp',
    mode: 'flood',
    expected: 'mixed',
    server: {
      rateLimitPerMinute: 5
    },
    client: {
      count: 8
    }
  },
  totp: {
    title: 'Multi-factor authentication (TOTP) valid token',
    profile: 'xapp',
    mode: 'totp',
    expected: 'accepted'
  },
  'totp-invalid': {
    title: 'Multi-factor authentication (TOTP) invalid token rejection',
    profile: 'xapp',
    mode: 'totp-invalid',
    expected: 'rejected'
  }
};

export async function runScenario(name) {
  ensurePki();

  const scenario = scenarios[name];
  if (!scenario) {
    throw new Error(`unknown demo scenario: ${name}`);
  }

  console.log(`\n=== ${scenario.title} ===`);
  const pipePath = process.platform === 'win32' ? `\\\\.\\pipe\\oran-cti-${process.pid}-${name}` : undefined;
  const ric = await startRicServer({
    port: pipePath ? undefined : 0,
    pipePath,
    ...(scenario.server ?? {})
  });
  const address = ric.server.address();

  try {
    const responses = await runXapp({
      port: typeof address === 'object' && address ? address.port : undefined,
      pipePath,
      profile: scenario.profile,
      mode: scenario.mode,
      ...(scenario.client ?? {})
    });
    summarizeScenario(name, responses);
    return responses;
  } finally {
    await ric.close();
  }
}

function ensurePki() {
  if (existsSync(defaultPaths.caCert) && existsSync(defaultPaths.pins)) {
    return;
  }

  console.log('[demo] generated certificates not found; running npm run pki first');
  const result = spawnSync(process.execPath, ['scripts/generate-pki.js'], {
    stdio: 'inherit'
  });

  if (result.status !== 0) {
    throw new Error('failed to generate PKI');
  }
}

function summarizeScenario(name, responses) {
  const statuses = responses.map((response) => response.status).join(', ');
  console.log(`[demo:${name}] responses: ${statuses}`);
}

async function main() {
  const requested = process.argv[2] ?? 'all';
  const names = requested === 'all' ? ['legit', 'rogue', 'foreign', 'tamper', 'replay', 'flood', 'totp', 'totp-invalid'] : [requested];

  for (const name of names) {
    await runScenario(name);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`[demo] fatal: ${error.message}`);
    process.exitCode = 1;
  });
}
