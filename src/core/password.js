import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const PREFIX = 'scrypt-v1';
const KEY_LENGTH = 32;

function parsePasswordRecord(record) {
  const value = String(record ?? '').trim();
  if (!value.startsWith(PREFIX)) return null;

  if (value.includes('$')) {
    const parts = value.split('$');
    if (parts.length !== 3 || parts[0] !== PREFIX) return null;
    return { saltText: parts[1], digestText: parts[2] };
  }

  if (value.startsWith(`${PREFIX}.`)) {
    const parts = value.split('.');
    if (parts.length !== 3 || parts[0] !== PREFIX) return null;
    return { saltText: parts[1], digestText: parts[2] };
  }

  return null;
}

export function isPanelPasswordHashRecord(record) {
  return parsePasswordRecord(record) !== null;
}

export function hashPanelPassword(password, salt = randomBytes(16)) {
  const value = String(password ?? '');
  if (value.length < 8) throw new Error('面板密码至少需要 8 个字符');
  const normalizedSalt = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt), 'base64url');
  const digest = scryptSync(value, normalizedSalt, KEY_LENGTH);
  return `${PREFIX}.${normalizedSalt.toString('base64url')}.${digest.toString('base64url')}`;
}

export function verifyPanelPassword(password, record) {
  const parsed = parsePasswordRecord(record);
  if (!parsed) return false;
  try {
    const expected = Buffer.from(parsed.digestText, 'base64url');
    const actual = scryptSync(String(password ?? ''), Buffer.from(parsed.saltText, 'base64url'), expected.length);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}
