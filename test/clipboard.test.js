import test from 'node:test';
import assert from 'node:assert/strict';
import { copyText } from '../public/clipboard.js';

test('安全上下文优先使用现代剪贴板接口', async () => {
  let copied = null;
  const result = await copyText('install command', {
    isSecureContext: true,
    navigator: { clipboard: { writeText: async (value) => { copied = value; } } },
  });
  assert.equal(copied, 'install command');
  assert.equal(result.method, 'clipboard');
});

test('纯 HTTP 或剪贴板权限受限时使用页面内兼容复制', async () => {
  const textarea = {
    style: {},
    setAttribute() {},
    focus() {},
    select() {},
    setSelectionRange() {},
    remove() { this.removed = true; },
  };
  const document = {
    activeElement: { focus() {} },
    body: { append(element) { element.appended = true; } },
    createElement(name) { assert.equal(name, 'textarea'); return textarea; },
    execCommand(command) { assert.equal(command, 'copy'); return true; },
  };
  const result = await copyText('curl command', { isSecureContext: false, document });
  assert.equal(textarea.value, 'curl command');
  assert.equal(textarea.appended, true);
  assert.equal(textarea.removed, true);
  assert.equal(result.method, 'compatibility');
});

test('浏览器完全拒绝复制时返回明确提示', async () => {
  const textarea = {
    style: {}, setAttribute() {}, focus() {}, select() {}, setSelectionRange() {}, remove() {},
  };
  await assert.rejects(copyText('command', {
    isSecureContext: false,
    document: {
      body: { append() {} },
      createElement: () => textarea,
      execCommand: () => false,
    },
  }), /手动复制/);
});
