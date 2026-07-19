import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WireGuardArtifactStore, wireGuardRuntimeManifest } from '../src/center/wireguard-artifacts.js';

test('中心校验并缓存 PathWeaver 私有 WireGuard 源码制品', async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), 'pathweaver-artifact-'));
  const content = Buffer.from('wireguard-runtime-fixture');
  const descriptor = {
    name: 'wireguard-tools-test.tar.xz',
    sourceUrl: 'https://wireguard.invalid/test.tar.xz',
    sha256: createHash('sha256').update(content).digest('hex'),
    contentType: 'application/x-xz',
  };
  let fetches = 0;
  const store = new WireGuardArtifactStore(cacheDir, {
    catalog: [descriptor],
    fetchImpl: async () => {
      fetches += 1;
      return new Response(content);
    },
  });
  try {
    const [downloaded, sharedDownload] = await Promise.all([
      store.load(descriptor.name),
      store.load(descriptor.name),
    ]);
    const cached = await store.load(descriptor.name);
    assert.equal(downloaded.cached, false);
    assert.equal(sharedDownload.cached, false);
    assert.equal(cached.cached, true);
    assert.deepEqual(cached.content, content);
    assert.equal(fetches, 1);
    assert.equal(wireGuardRuntimeManifest().toolsVersion, '1.0.20260223');
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
});

test('中心拒绝哈希不匹配的 WireGuard 制品', async () => {
  const cacheDir = mkdtempSync(join(tmpdir(), 'pathweaver-artifact-bad-'));
  const store = new WireGuardArtifactStore(cacheDir, {
    catalog: [{
      name: 'bad.tar.xz', sourceUrl: 'https://wireguard.invalid/bad.tar.xz', sha256: '0'.repeat(64),
    }],
    fetchImpl: async () => new Response('tampered'),
  });
  try {
    await assert.rejects(store.load('bad.tar.xz'), /SHA-256 校验失败/);
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
});
