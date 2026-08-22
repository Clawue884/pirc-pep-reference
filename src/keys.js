import crypto from 'node:crypto';

export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
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
