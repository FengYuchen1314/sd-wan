export function parseIPv4(value) {
  if (typeof value !== 'string') throw new Error('IPv4 地址必须是字符串');
  const parts = value.trim().split('.');
  if (parts.length !== 4) throw new Error(`无效的 IPv4 地址：${value}`);

  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) throw new Error(`无效的 IPv4 地址：${value}`);
    const octet = Number(part);
    if (octet < 0 || octet > 255) throw new Error(`无效的 IPv4 地址：${value}`);
    result = (result * 256) + octet;
  }
  return result >>> 0;
}

export function formatIPv4(value) {
  const number = Number(value) >>> 0;
  return [24, 16, 8, 0].map((shift) => (number >>> shift) & 255).join('.');
}

export function parseCIDR(value) {
  if (typeof value !== 'string' || !value.includes('/')) {
    throw new Error(`无效的 IPv4 CIDR：${value}`);
  }
  const [address, prefixText] = value.trim().split('/');
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`无效的 IPv4 CIDR：${value}`);
  }
  const ip = parseIPv4(address);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return {
    address: formatIPv4(ip),
    prefix,
    network,
    broadcast,
    cidr: `${formatIPv4(network)}/${prefix}`,
  };
}

export function containsIPv4(cidr, address) {
  const parsed = typeof cidr === 'string' ? parseCIDR(cidr) : cidr;
  const ip = typeof address === 'string' ? parseIPv4(address) : address;
  return ip >= parsed.network && ip <= parsed.broadcast;
}

export function usableHost(cidr, offset) {
  const parsed = typeof cidr === 'string' ? parseCIDR(cidr) : cidr;
  const value = parsed.network + Number(offset);
  if (!Number.isInteger(offset) || offset < 1 || value >= parsed.broadcast) {
    throw new Error(`${parsed.cidr} 中不存在主机偏移 ${offset}`);
  }
  return formatIPv4(value);
}

export function assertUsableHost(cidr, address, label = 'IP 地址') {
  const parsed = typeof cidr === 'string' ? parseCIDR(cidr) : cidr;
  const ip = parseIPv4(address);
  if (!containsIPv4(parsed, ip) || ip === parsed.network || ip === parsed.broadcast) {
    throw new Error(`${label} ${address} 不在可用网段 ${parsed.cidr} 内`);
  }
  return formatIPv4(ip);
}
