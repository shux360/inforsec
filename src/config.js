import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export const defaultPaths = {
  caCert: join(rootDir, 'certs', 'ca.cert.pem'),
  ricCert: join(rootDir, 'certs', 'ric.cert.pem'),
  ricKey: join(rootDir, 'certs', 'ric.key.pem'),
  xappCert: join(rootDir, 'certs', 'xapp.cert.pem'),
  xappKey: join(rootDir, 'certs', 'xapp.key.pem'),
  xappSigningKey: join(rootDir, 'certs', 'xapp-signing.key.pem'),
  rogueCert: join(rootDir, 'certs', 'rogue.cert.pem'),
  rogueKey: join(rootDir, 'certs', 'rogue.key.pem'),
  rogueSigningKey: join(rootDir, 'certs', 'rogue-signing.key.pem'),
  foreignCert: join(rootDir, 'certs', 'foreign.cert.pem'),
  foreignKey: join(rootDir, 'certs', 'foreign.key.pem'),
  pins: join(rootDir, 'certs', 'pins.json'),
  revoked: join(rootDir, 'config', 'revoked.json'),
  auditLog: join(rootDir, 'logs', 'audit.log'),
  samplePayload: join(rootDir, 'samples', 'stix-threat-indicator.json')
};

export function runtimeConfig(overrides = {}) {
  return {
    host: overrides.host ?? process.env.RIC_HOST ?? '127.0.0.1',
    port: Number(overrides.port ?? process.env.RIC_PORT ?? 9443),
    pipePath: overrides.pipePath ?? process.env.RIC_PIPE,
    serverIdentity: overrides.serverIdentity ?? process.env.RIC_SERVER_IDENTITY,
    maxSkewSeconds: Number(overrides.maxSkewSeconds ?? process.env.RIC_MAX_SKEW_SECONDS ?? 30),
    rateLimitPerMinute: Number(overrides.rateLimitPerMinute ?? process.env.RIC_RATE_LIMIT_PER_MINUTE ?? 30),
    demoPort: Number(overrides.demoPort ?? process.env.RIC_DEMO_PORT ?? 8080),
    demoSecret: overrides.demoSecret ?? process.env.RIC_DEMO_SECRET ?? 'demo-secret',
    demoApiKey: overrides.demoApiKey ?? process.env.RIC_DEMO_API_KEY ?? 'inforsec-demo-key',
    paths: {
      ...defaultPaths,
      ...(overrides.paths ?? {})
    }
  };
}
