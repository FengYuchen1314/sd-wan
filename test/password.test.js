import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, scryptSync } from 'node:crypto';
import { hashPanelPassword, verifyPanelPassword } from '../src/core/password.js';

test('面板密码使用带随机盐的 scrypt 摘要保存和验证', () => {
  const first = hashPanelPassword('correct-horse-battery-staple');
  const second = hashPanelPassword('correct-horse-battery-staple');
  assert.match(first, /^scrypt-v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.doesNotMatch(first, /\$/);
  assert.notEqual(first, second);
  assert.equal(verifyPanelPassword('correct-horse-battery-staple', first), true);
  assert.equal(verifyPanelPassword('wrong-password', first), false);
  assert.equal(verifyPanelPassword('correct-horse-battery-staple', 'invalid'), false);
  assert.throws(() => hashPanelPassword('short'), /至少需要 8 个字符/);
});

test('面板密码验证兼容旧版 $ 分隔哈希', () => {
  const password = 'legacy-panel-password';
  const salt = randomBytes(16);
  const digest = scryptSync(password, salt, 32);
  const legacy = `scrypt-v1$${salt.toString('base64url')}$${digest.toString('base64url')}`;
  assert.equal(verifyPanelPassword(password, legacy), true);
  assert.equal(verifyPanelPassword('wrong-password', legacy), false);
});
