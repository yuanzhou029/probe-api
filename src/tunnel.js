import net from 'node:net';
import tls from 'node:tls';
import { ByteReader, concatBytes, withTimeout } from './util.js';
import { stripIPv6Brackets, isIPHostname } from './parse.js';
import { CONNECT_TIMEOUT_MS } from './config.js';
import { sstpConnect } from './sstp.js';

const SOCKS5_REPLY = {
	1: 'general SOCKS server failure',
	2: 'connection not allowed by ruleset',
	3: 'network unreachable',
	4: 'host unreachable',
	5: 'connection refused',
	6: 'TTL expired',
	7: 'command not supported',
	8: 'address type not supported'
};

export function dialTcp(host, port, timeoutMs = CONNECT_TIMEOUT_MS) {
	return new Promise((resolve, reject) => {
		const socket = net.connect({ host, port });
		const timer = setTimeout(() => {
			socket.destroy();
			reject(new Error(`代理 TCP 连接超时 ${host}:${port}`));
		}, timeoutMs);

		socket.once('connect', () => {
			clearTimeout(timer);
			socket.removeAllListeners('error');
			// 保持一个空监听，避免后续 destroy 触发未捕获的 error 事件导致进程退出
			socket.on('error', () => { });
			socket.setNoDelay(true);
			resolve(socket);
		});
		socket.once('error', error => {
			clearTimeout(timer);
			reject(new Error(`代理 TCP 连接失败 ${host}:${port}: ${error.message}`));
		});
	});
}

/**
 * 与代理本体建立 TLS。worker 里的手写 TLS 客户端不校验证书，
 * 这里保持一致（HTTPS 代理普遍使用自签证书）。
 */
export async function dialTls(host, port, serverName, timeoutMs = CONNECT_TIMEOUT_MS) {
	const socket = await dialTcp(host, port, timeoutMs);
	socket.on('error', () => { });

	return new Promise((resolve, reject) => {
		const secure = tls.connect({
			socket,
			servername: serverName || undefined,
			rejectUnauthorized: false,
			ALPNProtocols: ['http/1.1']
		});
		const timer = setTimeout(() => {
			secure.destroy();
			reject(new Error(`代理 TLS 握手超时 ${host}:${port}`));
		}, timeoutMs);

		secure.once('secureConnect', () => {
			clearTimeout(timer);
			secure.on('error', () => { });
			resolve(secure);
		});
		secure.once('error', error => {
			clearTimeout(timer);
			reject(new Error(`代理 TLS 握手失败 ${host}:${port}: ${error.message}`));
		});
	});
}

export async function socks5Connect(proxy, targetHost, targetPort) {
	const socket = await dialTcp(stripIPv6Brackets(proxy.hostname), proxy.port);
	const reader = new ByteReader(socket, { timeoutMs: CONNECT_TIMEOUT_MS });

	try {
		const withAuth = proxy.username !== null && proxy.password !== null;
		socket.write(withAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]));

		const greeting = await reader.readExactly(2);
		if (greeting[0] !== 0x05) throw new Error('SOCKS5 握手响应版本不正确');
		const method = greeting[1];

		if (method === 0x02) {
			if (!withAuth) throw new Error('SOCKS5 要求认证但未提供账号密码');
			const user = Buffer.from(proxy.username, 'utf8');
			const pass = Buffer.from(proxy.password, 'utf8');
			if (user.length > 255 || pass.length > 255) throw new Error('SOCKS5 用户名或密码过长');
			socket.write(concatBytes(Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass));
			const authReply = await reader.readExactly(2);
			if (authReply[1] !== 0x00) throw new Error('SOCKS5 用户名密码认证失败');
		} else if (method === 0xff) {
			// 0xFF = 服务端认为没有一个可接受的认证方式：要么它要密码而我们只报了 0x00，要么账号密码被拒
			throw new Error(withAuth
				? 'SOCKS5 服务端拒绝了全部认证方式（0xFF），账号密码可能不被接受'
				: 'SOCKS5 服务端拒绝了无认证方式（0xFF），该节点需要账号密码，请改用 proxy=socks5://user:pass@host:port');
		} else if (method !== 0x00) {
			throw new Error(`SOCKS5 不支持该认证方式: ${method}`);
		}

		const hostBytes = Buffer.from(targetHost, 'utf8');
		if (hostBytes.length > 255) throw new Error('目标域名过长');
		socket.write(concatBytes(
			Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
			hostBytes,
			Buffer.from([targetPort >> 8, targetPort & 0xff])
		));

		const head = await reader.readExactly(4);
		if (head[0] !== 0x05) throw new Error('SOCKS5 CONNECT 响应版本不正确');
		if (head[1] !== 0x00) throw new Error(`SOCKS5 连接失败: ${SOCKS5_REPLY[head[1]] || `reply=${head[1]}`}`);

		// 把 BND.ADDR + BND.PORT 一起读干净，避免污染后续 TLS 数据
		let addressLength = 0;
		if (head[3] === 0x01) addressLength = 4;
		else if (head[3] === 0x04) addressLength = 16;
		else if (head[3] === 0x03) addressLength = (await reader.readExactly(1))[0];
		else throw new Error(`SOCKS5 地址类型不受支持: ${head[3]}`);
		await reader.readExactly(addressLength + 2);

		reader.detach();
		return socket;
	} catch (error) {
		socket.destroy();
		throw error;
	}
}

async function httpConnectOver(stream, proxy, targetHost, targetPort, label) {
	const reader = new ByteReader(stream, { timeoutMs: CONNECT_TIMEOUT_MS });
	try {
		const auth = proxy.username !== null && proxy.password !== null
			? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}\r\n`
			: '';
		stream.write(Buffer.from(
			`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`
			+ `Host: ${targetHost}:${targetPort}\r\n`
			+ `${auth}User-Agent: Mozilla/5.0\r\n`
			+ 'Proxy-Connection: keep-alive\r\n'
			+ 'Connection: keep-alive\r\n\r\n',
			'latin1'
		));

		const headerText = (await reader.readUntil('\r\n\r\n')).toString('latin1');
		const statusLine = headerText.split('\r\n')[0] || '';
		const statusMatch = statusLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
		const statusCode = statusMatch ? Number(statusMatch[1]) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
			throw new Error(`${label} CONNECT 失败: ${statusLine || '无效响应'}`);
		}

		reader.detach();
		return stream;
	} catch (error) {
		stream.destroy();
		throw error;
	}
}

export function httpConnect(proxy, targetHost, targetPort) {
	const stream = dialTcp(stripIPv6Brackets(proxy.hostname), proxy.port);
	return stream.then(socket => httpConnectOver(socket, proxy, targetHost, targetPort, 'HTTP'));
}

export async function httpsConnect(proxy, targetHost, targetPort) {
	const serverName = isIPHostname(proxy.hostname) ? '' : stripIPv6Brackets(proxy.hostname);
	const stream = await dialTls(stripIPv6Brackets(proxy.hostname), proxy.port, serverName);
	return httpConnectOver(stream, proxy, targetHost, targetPort, 'HTTPS');
}

/** 统一入口：返回一个已完成代理握手的双工流，可直接交给 tls.connect 使用 */
export async function createTunnel(proxy, targetHost, targetPort) {
	let stream;
	if (proxy.type === 'socks5') {
		stream = await socks5Connect(proxy, targetHost, targetPort);
	} else if (proxy.type === 'http') {
		stream = await httpConnect(proxy, targetHost, targetPort);
	} else if (proxy.type === 'https') {
		stream = await httpsConnect(proxy, targetHost, targetPort);
	} else if (proxy.type === 'sstp') {
		stream = await withTimeout(sstpConnect(proxy, targetHost, targetPort), CONNECT_TIMEOUT_MS, 'SSTP 隧道建立超时');
	} else {
		throw new Error(`不支持的代理类型: ${proxy.type}`);
	}
	return stream;
}
