import { createSocket } from 'node:dgram';
import { createServer } from 'node:net';

export const DEFAULT_DATA_PORT = 19801;
export const MAX_PROBE_HOPS = 16;

export function normalizeDataPort(value, label = 'WireGuard 端口') {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${label}必须是 1 到 65535 的整数`);
  }
  return port;
}

export function isUdpPortAvailable(port, host = '0.0.0.0') {
  const normalizedPort = normalizeDataPort(port);
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4');
    socket.once('error', (error) => {
      if (error.code === 'EADDRINUSE' || error.code === 'EACCES') resolve(false);
      else reject(error);
    });
    socket.once('listening', () => socket.close(() => resolve(true)));
    socket.bind({ port: normalizedPort, address: host, exclusive: true });
  });
}

export async function selectAvailableUdpPort({
  preferred = DEFAULT_DATA_PORT,
  strict = false,
  host = '0.0.0.0',
  searchSpan = 1024,
} = {}) {
  const firstPort = normalizeDataPort(preferred);
  const lastPort = strict ? firstPort : Math.min(65535, firstPort + Math.max(0, Number(searchSpan) || 0));
  for (let port = firstPort; port <= lastPort; port += 1) {
    if (await isUdpPortAvailable(port, host)) return port;
  }
  if (strict) throw new Error(`指定的 WireGuard UDP 端口 ${firstPort} 已被占用或不可用`);
  throw new Error(`从 ${firstPort} 开始未找到可用的 WireGuard UDP 端口`);
}

export function isTcpPortAvailable(port, host = '0.0.0.0') {
  const normalizedPort = normalizeDataPort(port, 'TCP 端口');
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', (error) => {
      if (error.code === 'EADDRINUSE' || error.code === 'EACCES') resolve(false);
      else reject(error);
    });
    server.once('listening', () => server.close(() => resolve(true)));
    server.listen({ port: normalizedPort, host, exclusive: true });
  });
}

export async function selectAvailableTcpPort({
  preferred = 8790,
  strict = false,
  host = '0.0.0.0',
  searchSpan = 1024,
} = {}) {
  const firstPort = normalizeDataPort(preferred, 'TCP 端口');
  const lastPort = strict ? firstPort : Math.min(65535, firstPort + Math.max(0, Number(searchSpan) || 0));
  for (let port = firstPort; port <= lastPort; port += 1) {
    if (await isTcpPortAvailable(port, host)) return port;
  }
  if (strict) throw new Error(`指定的 TCP 端口 ${firstPort} 已被占用或不可用`);
  throw new Error(`从 ${firstPort} 开始未找到可用的 TCP 端口`);
}

function normalizeTrace(trace, maxHops) {
  if (trace === undefined || trace === null) return [];
  if (!Array.isArray(trace) || trace.some((nodeId) => typeof nodeId !== 'string' || !nodeId)) {
    throw new Error('探测访问轨迹格式无效');
  }
  if (trace.length >= maxHops) throw new Error(`探测已达到 ${maxHops} 跳上限`);
  return trace;
}

export function acceptProbeEnvelope(input, nodeId, maxHops = MAX_PROBE_HOPS) {
  const probeId = String(input?.probeId ?? '').trim();
  if (!probeId || probeId.length > 128) throw new Error('探测 ID 无效');
  const trace = normalizeTrace(input?.trace, maxHops);
  if (trace.includes(nodeId)) throw new Error('检测到探测环路，已终止本次请求');
  const remainingHops = Number(input?.remainingHops);
  if (!Number.isInteger(remainingHops) || remainingHops < 1 || remainingHops > maxHops) {
    throw new Error(`探测剩余跳数无效或已超过 ${maxHops} 跳上限`);
  }
  return {
    probeId,
    trace: [...trace, nodeId],
    remainingHops: remainingHops - 1,
  };
}

export function extendRelayTrace(value, nodeId, maxHops = MAX_PROBE_HOPS) {
  const trace = String(value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  if (trace.includes(nodeId)) throw new Error('检测到控制中继环路，已停止转发');
  if (trace.length >= maxHops) throw new Error(`控制中继已达到 ${maxHops} 跳上限`);
  return [...trace, nodeId].join(',');
}
