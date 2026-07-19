import test from 'node:test';
import assert from 'node:assert/strict';
import { assertUsableHost, containsIPv4, formatIPv4, parseCIDR, parseIPv4, usableHost } from '../src/core/ipv4.js';

test('IPv4 与 CIDR 规范化和主机分配', () => {
  assert.equal(formatIPv4(parseIPv4('10.77.1.9')), '10.77.1.9');
  assert.deepEqual(parseCIDR('10.77.3.4/16'), {
    address: '10.77.3.4',
    prefix: 16,
    network: parseIPv4('10.77.0.0'),
    broadcast: parseIPv4('10.77.255.255'),
    cidr: '10.77.0.0/16',
  });
  assert.equal(usableHost('10.77.0.0/24', 25), '10.77.0.25');
  assert.equal(containsIPv4('10.77.0.0/24', '10.77.0.200'), true);
  assert.equal(containsIPv4('10.77.0.0/24', '10.77.1.1'), false);
  assert.equal(assertUsableHost('10.77.0.0/24', '10.77.0.8'), '10.77.0.8');
});

test('拒绝非法 IPv4 和网络/广播地址', () => {
  assert.throws(() => parseIPv4('10.1.2.999'), /无效/);
  assert.throws(() => parseCIDR('10.1.2.3/35'), /无效/);
  assert.throws(() => assertUsableHost('10.1.2.0/24', '10.1.2.0'), /不在可用网段/);
  assert.throws(() => assertUsableHost('10.1.2.0/24', '10.1.2.255'), /不在可用网段/);
});
