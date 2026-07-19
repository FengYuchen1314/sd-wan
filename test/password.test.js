import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPanelPassword, verifyPanelPassword } from '../src/core/password.js';

test('面板密码使用带随机盐的 scrypt 摘要保存和验证', () => {
  const first = hashPanelPassword('correct-horse-battery-staple');
  const second = hashPanelPassword('correct-horse-battery-staple');
  assert.match(first, /^scrypt-v1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.notEqual(first, second);
  assert.equal(verifyPanelPassword('correct-horse-battery-staple', first), true);
  assert.equal(verifyPanelPassword('wrong-password', first), false);
  assert.equal(verifyPanelPassword('correct-horse-battery-staple', 'invalid'), false);
  assert.throws(() => hashPanelPassword('short'), /至少需要 8 个字符/);
});
