import crypto from 'node:crypto';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function generateKeyPair({ seed } = {}) {
  let privateKey;
  if (seed === undefined) {
    privateKey = crypto.generateKeyPairSync('ed25519').privateKey;
  } else {
    const s = typeof seed === 'string' ? Buffer.from(seed, 'hex') : Buffer.from(seed);
    if (s.length !== 32) {
      throw new TypeError('Ed25519 seed must be exactly 32 bytes');
    }
    privateKey = crypto.createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519_PREFIX, s]),
      format: 'der',
      type: 'pkcs8'
    });
  }
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }),
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}

export function publicKeyFingerprint(publicKeyPem) {
  const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url').toString('hex');
}

export function signMessage(privateKeyPem, messageBytes) {
  const key = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, messageBytes, key);
}

export function verifySignature(publicKeyPem, messageBytes, signatureBytes) {
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, messageBytes, key, signatureBytes);
  } catch {
    return false;
  }
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

export function randomNonce() {
  return crypto.randomBytes(16).toString('hex');
}
