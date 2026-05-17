import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const certsDir = join(rootDir, 'certs');
const tmpDir = join(certsDir, '.tmp');
let baseConfigPath;
const ricSubjectAltName = buildSubjectAltName();

function run(args) {
  const result = spawnSync('openssl', args, {
    cwd: rootDir,
    encoding: 'utf8',
    shell: false
  });

  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    throw new Error(`openssl ${args.join(' ')} failed`);
  }

  if (process.env.DEBUG_OPENSSL === '1') {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
  }
}

function writeConfig(name, content) {
  const path = join(tmpDir, name);
  writeFileSync(path, content.trimStart(), 'utf8');
  return path;
}

function generateEcKey(path) {
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', path]);
}

function generateRsaKey(path) {
  run(['genrsa', '-out', path, '3072']);
}

function generateSignedCert({ name, subject, extConfig, keyType = 'rsa' }) {
  const keyPath = join(certsDir, `${name}.key.pem`);
  const csrPath = join(tmpDir, `${name}.csr.pem`);
  const certPath = join(certsDir, `${name}.cert.pem`);
  const extPath = writeConfig(`${name}.ext.cnf`, extConfig);

  if (keyType === 'ec') {
    generateEcKey(keyPath);
  } else {
    generateRsaKey(keyPath);
  }
  run(['req', '-new', '-config', baseConfigPath, '-key', keyPath, '-out', csrPath, '-subj', subject]);
  run([
    'x509',
    '-req',
    '-in',
    csrPath,
    '-CA',
    join(certsDir, 'ca.cert.pem'),
    '-CAkey',
    join(certsDir, 'ca.key.pem'),
    '-CAcreateserial',
    '-out',
    certPath,
    '-days',
    '825',
    '-sha256',
    '-extfile',
    extPath
  ]);

  return { keyPath, certPath };
}

function generateSigningKey(name) {
  const keyPath = join(certsDir, `${name}-signing.key.pem`);
  const publicKeyPath = join(certsDir, `${name}-signing.public.pem`);
  generateEcKey(keyPath);
  run(['ec', '-in', keyPath, '-pubout', '-out', publicKeyPath]);
  return { keyPath, publicKeyPath };
}

function buildSubjectAltName() {
  const dnsNames = (process.env.RIC_CERT_DNS ?? 'localhost')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => `DNS:${value}`);
  const ipAddresses = (process.env.RIC_CERT_IPS ?? '127.0.0.1,54.242.77.97')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => `IP:${value}`);
  return [...dnsNames, ...ipAddresses].join(',');
}

function fingerprint(path) {
  const cert = new X509Certificate(readFileSync(path));
  return cert.fingerprint256.replaceAll(':', '').toUpperCase();
}

rmSync(certsDir, { recursive: true, force: true });
mkdirSync(tmpDir, { recursive: true });

baseConfigPath = writeConfig(
  'openssl.cnf',
  `
[ req ]
distinguished_name = req_distinguished_name
string_mask = utf8only
prompt = no

[ req_distinguished_name ]

[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
`
);

generateRsaKey(join(certsDir, 'ca.key.pem'));
run([
  'req',
  '-x509',
  '-new',
  '-config',
  baseConfigPath,
  '-extensions',
  'v3_ca',
  '-key',
  join(certsDir, 'ca.key.pem'),
  '-sha256',
  '-days',
  '3650',
  '-out',
  join(certsDir, 'ca.cert.pem'),
  '-subj',
  '/C=LK/O=EC7201 O-RAN CTI/OU=Demo PKI/CN=O-RAN CTI Demo Root CA'
]);

generateSignedCert({
  name: 'ric',
  subject: '/C=LK/O=EC7201 O-RAN CTI/OU=Near-RT RIC/CN=localhost',
  extConfig: `
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${ricSubjectAltName}
`
});

generateSignedCert({
  name: 'xapp',
  subject: '/C=LK/O=EC7201 O-RAN CTI/OU=Trusted xApps/CN=xapp-legitimate',
  extConfig: `
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:xapp-legitimate,URI:spiffe://oran-cti/xapp-legitimate
`
});

generateSignedCert({
  name: 'rogue',
  subject: '/C=LK/O=EC7201 O-RAN CTI/OU=Unpinned xApps/CN=xapp-rogue',
  extConfig: `
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:xapp-rogue,URI:spiffe://oran-cti/xapp-rogue
`
});

generateSigningKey('xapp');
generateSigningKey('rogue');

generateEcKey(join(certsDir, 'foreign.key.pem'));
run([
  'req',
  '-x509',
  '-new',
  '-config',
  baseConfigPath,
  '-key',
  join(certsDir, 'foreign.key.pem'),
  '-sha256',
  '-days',
  '365',
  '-out',
  join(certsDir, 'foreign.cert.pem'),
  '-subj',
  '/C=LK/O=Untrusted External/CN=xapp-foreign-self-signed'
]);

writeFileSync(
  join(certsDir, 'pins.json'),
  `${JSON.stringify(
    {
      xapps: {
        'xapp-legitimate': {
          tlsFingerprint: fingerprint(join(certsDir, 'xapp.cert.pem')),
          signingPublicKey: 'certs/xapp-signing.public.pem',
          totpSecret: 'JBSWY3DPEHPK3PXP'
        }
      }
    },
    null,
    2
  )}\n`,
  'utf8'
);

rmSync(tmpDir, { recursive: true, force: true });

console.log('\nGenerated demo PKI in certs/:');
console.log(`  CA:        ${join(certsDir, 'ca.cert.pem')}`);
console.log(`  RIC:       ${join(certsDir, 'ric.cert.pem')}`);
console.log(`  xApp pin:  ${fingerprint(join(certsDir, 'xapp.cert.pem'))}`);
console.log(`  Rogue pin: ${fingerprint(join(certsDir, 'rogue.cert.pem'))} (intentionally not trusted)`);
