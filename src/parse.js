// 代理地址解析，逐条对应 _worker.js:1540-1678 的行为，保持输入格式完全兼容：
//   socks5://user:pass@host:1080、http://host:8080、sstp://vpn:vpn@host:443、
//   host:port、[2001:db8::1]:1080、以及 Base64 形式的 user:pass。

export const PROXY_TYPES = ['socks5', 'http', 'https', 'sstp'];

export const DEFAULT_PORTS = {
	socks5: 1080,
	http: 80,
	https: 443,
	sstp: 443
};

const BASE64_AUTH_RE = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;

export function safeDecode(value) {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

export function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

export function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => {
		if (!/^\d{1,3}$/.test(part)) return false;
		const num = Number(part);
		return num >= 0 && num <= 255;
	});
}

export function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch {
		return false;
	}
}

export function splitProxyScheme(input) {
	const text = String(input || '').trim();
	const match = text.match(/^(socks5|http|https|sstp):\/\/(.+)$/i);
	return match ? { type: match[1].toLowerCase(), rest: match[2] } : null;
}

export function stripProxyScheme(input) {
	return String(input || '').replace(/^(socks5|http|https|sstp):\/\//i, '');
}

export function formatProxyAuthority(proxy) {
	const auth = proxy.username !== null && proxy.password !== null ? `${proxy.username}:${proxy.password}@` : '';
	return `${auth}${proxy.hostname}:${proxy.port}`;
}

export function parseProxyAddress(input, type, defaultPort = 80) {
	let address = stripProxyScheme(String(input || '').trim()).split('#')[0].trim();
	if (!address) throw new Error('代理地址不能为空');

	const atIndex = address.lastIndexOf('@');
	let authPart = '';
	let hostPart = address;
	if (atIndex !== -1) {
		authPart = address.slice(0, atIndex).replaceAll('%3D', '=');
		if (!authPart.includes(':') && BASE64_AUTH_RE.test(authPart)) {
			try {
				authPart = Buffer.from(authPart, 'base64').toString('utf8');
			} catch {
				/* 解不出来就按原文处理 */
			}
		}
		hostPart = address.slice(atIndex + 1);
	}

	let username = null;
	let password = null;
	if (authPart) {
		const colonIndex = authPart.indexOf(':');
		if (colonIndex === -1) throw new Error('代理认证必须使用 username:password 格式');
		username = safeDecode(authPart.slice(0, colonIndex));
		password = safeDecode(authPart.slice(colonIndex + 1));
	}

	hostPart = hostPart.split('/')[0].trim();
	let hostname = hostPart;
	let port = defaultPort;
	if (hostPart.startsWith('[')) {
		const closeIndex = hostPart.indexOf(']');
		if (closeIndex === -1) throw new Error('IPv6 地址缺少右括号');
		hostname = hostPart.slice(0, closeIndex + 1);
		if (hostPart.slice(closeIndex + 1).startsWith(':')) {
			port = Number(hostPart.slice(closeIndex + 2).replace(/\D/g, ''));
		}
	} else {
		const colonCount = (hostPart.match(/:/g) || []).length;
		if (colonCount === 1) {
			const separator = hostPart.lastIndexOf(':');
			hostname = hostPart.slice(0, separator);
			port = Number(hostPart.slice(separator + 1).replace(/\D/g, ''));
		} else if (colonCount > 1) {
			throw new Error('IPv6 地址必须用方括号包裹，例如 [2001:db8::1]:1080');
		}
	}

	hostname = safeDecode(hostname.trim());
	if (!hostname) throw new Error('缺少代理主机名');
	if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口必须是 1-65535 之间的整数');
	if (hostname.includes(':') && !hostname.startsWith('[')) throw new Error('IPv6 地址必须用方括号包裹');

	return { type, username, password, hostname, port };
}
