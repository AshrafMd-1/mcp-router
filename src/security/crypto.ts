import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

interface EncryptedEnvelopeV1 {
  v: 1;
  alg: 'aes-256-gcm';
  iv: string;
  tag: string;
  ct: string;
}

function parseKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (/^[a-fA-F0-9]+$/.test(trimmed) && trimmed.length === 64) {
    return Buffer.from(trimmed, 'hex');
  }

  const base64 = Buffer.from(trimmed, 'base64');
  if (base64.length === 32) {
    return base64;
  }

  throw new Error('ENCRYPTION_KEY must be 32-byte base64 or 64-char hex');
}

export function createEncryptionContext(rawKey: string) {
  const key = parseKey(rawKey);

  return {
    encrypt(payload: Record<string, unknown>): Buffer {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const json = Buffer.from(JSON.stringify(payload), 'utf-8');
      const ct = Buffer.concat([cipher.update(json), cipher.final()]);
      const tag = cipher.getAuthTag();

      const envelope: EncryptedEnvelopeV1 = {
        v: 1,
        alg: 'aes-256-gcm',
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ct: ct.toString('base64')
      };

      return Buffer.from(JSON.stringify(envelope), 'utf-8');
    },

    decrypt(blob: Buffer): Record<string, unknown> {
      const raw = blob.toString('utf-8');

      // Backward compatibility for plaintext legacy rows.
      if (raw.startsWith('{') && !raw.includes('"alg":"aes-256-gcm"')) {
        return JSON.parse(raw) as Record<string, unknown>;
      }

      const env = JSON.parse(raw) as EncryptedEnvelopeV1;
      if (env.v !== 1 || env.alg !== 'aes-256-gcm') {
        throw new Error('Unsupported encrypted payload format');
      }

      const iv = Buffer.from(env.iv, 'base64');
      const tag = Buffer.from(env.tag, 'base64');
      const ct = Buffer.from(env.ct, 'base64');

      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      const json = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
      return JSON.parse(json) as Record<string, unknown>;
    }
  };
}
