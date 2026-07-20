export const MAX_CONTROL_ROUTE_HOPS = 16;

export function normalizeControlEndpoint(value) {
  const parsed = new URL(String(value || ''));
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('控制路径只支持 HTTP 或 HTTPS');
  parsed.pathname = '/';
  parsed.search = '';
  parsed.hash = '';
  return parsed.href.replace(/\/$/, '');
}

function shuffled(values) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const other = Math.floor(Math.random() * (index + 1));
    [result[index], result[other]] = [result[other], result[index]];
  }
  return result;
}

export function encodeControlRouteHeader(route) {
  return Buffer.from(JSON.stringify(route), 'utf8').toString('base64url');
}

export async function fetchViaInternalControlRoutes({
  targetId,
  pathname,
  routesByTarget = {},
  forwarders = {},
  relayTrace = '',
  method = 'POST',
  headers = {},
  body,
  timeout = 12_000,
  resolveUrl = (url) => url,
  shuffleRoutes = true,
}) {
  if (!targetId) throw new Error('缺少目标节点 ID');
  const routes = shuffleRoutes
    ? shuffled(routesByTarget[targetId] || [])
    : (routesByTarget[targetId] || []);
  const failures = [];
  for (const route of routes) {
    if (!Array.isArray(route.hops) || !route.hops.length || route.hops.length > MAX_CONTROL_ROUTE_HOPS) continue;
    const [first, ...remaining] = route.hops;
    try {
      const firstUrl = normalizeControlEndpoint(first.url);
      if (forwarders[first.nodeId] !== firstUrl) continue;
      const response = await fetch(new URL(pathname, `${resolveUrl(firstUrl)}/`), {
        method,
        headers: {
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...(relayTrace ? { 'X-PathWeaver-Relay-Trace': relayTrace } : {}),
          ...(remaining.length ? { 'X-PathWeaver-Control-Route': encodeControlRouteHeader(remaining) } : {}),
          ...headers,
        },
        body,
        signal: AbortSignal.timeout(timeout),
      });
      const contentType = response.headers.get('content-type') ?? '';
      const parsed = contentType.includes('json') ? await response.json().catch(() => ({})) : await response.text();
      if (!response.ok) {
        throw new Error(parsed?.error || `内网控制路径返回 HTTP ${response.status}`);
      }
      return parsed;
    } catch (error) {
      failures.push(`${route.id}: ${error.message}`);
    }
  }
  const directUrl = forwarders[targetId] ? normalizeControlEndpoint(forwarders[targetId]) : null;
  if (directUrl) {
    try {
      const response = await fetch(new URL(pathname, `${resolveUrl(directUrl)}/`), {
        method,
        headers: {
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...(relayTrace ? { 'X-PathWeaver-Relay-Trace': relayTrace } : {}),
          ...headers,
        },
        body,
        signal: AbortSignal.timeout(timeout),
      });
      const contentType = response.headers.get('content-type') ?? '';
      const parsed = contentType.includes('json') ? await response.json().catch(() => ({})) : await response.text();
      if (!response.ok) {
        throw new Error(parsed?.error || `内网控制路径返回 HTTP ${response.status}`);
      }
      return parsed;
    } catch (error) {
      failures.push(`direct:${error.message}`);
    }
  }
  throw new Error(`到节点 ${targetId} 的内网控制路径均不可用：${failures.join('；')}`);
}
