import tls from 'node:tls';
import { createTunnel } from './tunnel.js';
import { ByteReader, concatBytes, withTimeout } from './util.js';
import { parseProxyAddress, formatProxyAuthority, stripProxyScheme, stripIPv6Brackets } from './parse.js';
import { CHECK_TIMEOUT_MS, READ_TIMEOUT_MS, MAX_RESPONSE_BYTES } from './config.js';

// 判定“存活”的方式与 _worker.js:216-373 完全一致：
// 通过代理建立隧道 → 对目标站点做真实 TLS 握手 → 请求 /api/lookup → 拿到出口 IP 才算活。
// 只测端口是否可连会把“需要认证的代理”“能连但无出口”的节点误判为可用。
const TARGET_HOST = process.env.TARGET_HOST || 'www.iplocate.io';
const TARGET_PORT = Number(process.env.TARGET_PORT || 443);
const TARGET_PATH = process.env.TARGET_PATH || '/api/lookup';

function decodeChunked(buffer) {
	const text = buffer.toString('utf8');
	let cursor = 0;
	let output = '';
	while (cursor < text.length) {
		const lineEnd = text.indexOf('\r\n', cursor);
		if (lineEnd === -1) break;
		const size = parseInt(text.slice(cursor, lineEnd).split(';')[0].trim(), 16);
		if (!Number.isFinite(size)) break;
		cursor = lineEnd + 2;
		if (size === 0) break;
		output += text.slice(cursor, cursor + size);
		cursor += size + 2;
	}
	return output;
}

async function readHttpResponse(reader) {
	const headerText = (await withTimeout(
		reader.readUntil('\r\n\r\n'),
		READ_TIMEOUT_MS,
		'读取目标响应头超时'
	)).toString('latin1');

	const statusLine = headerText.split('\r\n')[0] || '';
	const statusMatch = statusLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
	const statusCode = statusMatch ? Number(statusMatch[1]) : NaN;
	if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
		throw new Error(`目标站点请求失败: ${statusLine || '无效状态行'}`);
	}

	const lengthMatch = headerText.match(/\r\ncontent-length:\s*(\d+)/i);
	const chunked = /\r\ntransfer-encoding:\s*chunked/i.test(headerText);

	let body;
	if (lengthMatch) {
		const length = Math.min(Number(lengthMatch[1]), MAX_RESPONSE_BYTES);
		body = await withTimeout(reader.readExactly(length), READ_TIMEOUT_MS, '读取目标响应体超时');
	} else if (chunked) {
		let raw = Buffer.alloc(0);
		while (!raw.includes('\r\n0\r\n\r\n') && raw.length < MAX_RESPONSE_BYTES) {
			raw = concatBytes(raw, await withTimeout(reader.readSome(), READ_TIMEOUT_MS, '读取目标响应体超时'));
		}
		body = Buffer.from(decodeChunked(raw), 'utf8');
	} else {
		let raw = Buffer.alloc(0);
		while (raw.length < MAX_RESPONSE_BYTES) {
			try {
				raw = concatBytes(raw, await withTimeout(reader.readSome(), READ_TIMEOUT_MS, '读取目标响应体超时'));
			} catch {
				break;
			}
		}
		body = raw;
	}

	return body;
}

/** 把 iplocate.io 的响应整理成 worker 前端使用的字段（_worker.js:330-346） */
function normalizeExit(payload) {
	return {
		...payload,
		asn: payload.asn
			? { ...payload.asn, org: payload.asn.name, descr: payload.asn.name }
			: payload.asn,
		rir: payload.asn?.rir || null,
		is_datacenter: payload.privacy?.is_hosting || false,
		is_crawler: false,
		is_bogon: payload.privacy?.is_bogon || false,
		is_proxy: payload.privacy?.is_proxy || false,
		is_vpn: payload.privacy?.is_vpn || false,
		is_tor: payload.privacy?.is_tor || false,
		is_abuser: payload.privacy?.is_abuser || false
	};
}

export function buildCheckResult({ type, rawValue, proxy, success, exit = null, error = null, responseTime }) {
	const candidate = proxy ? formatProxyAuthority(proxy) : stripProxyScheme(rawValue);
	const result = {
		candidate,
		type,
		username: proxy?.username ?? null,
		password: proxy?.password ?? null,
		hostname: proxy?.hostname ?? null,
		port: proxy?.port ?? null,
		link: proxy ? `${proxy.type}://${formatProxyAuthority(proxy)}` : `${type}://${candidate}`,
		success,
		colo: null,
		responseTime,
		server: process.env.SERVER_NAME || 'vps'
	};
	if (success) result.exit = exit;
	else result.error = error || '代理探测失败';
	return result;
}

export async function checkProxy({ type, value }, defaultPort) {
	const startedAt = Date.now();
	let proxy = null;
	let tunnel = null;

	try {
		proxy = parseProxyAddress(value, type, defaultPort);
	} catch (error) {
		return buildCheckResult({
			type,
			rawValue: value,
			proxy: null,
			success: false,
			error: error.message,
			responseTime: Date.now() - startedAt
		});
	}

	try {
		tunnel = await withTimeout(
			createTunnel(proxy, TARGET_HOST, TARGET_PORT),
			CHECK_TIMEOUT_MS,
			'代理连接超时'
		);

		const secure = await new Promise((resolve, reject) => {
			const socket = tls.connect({
				socket: tunnel,
				servername: stripIPv6Brackets(TARGET_HOST),
				ALPNProtocols: ['http/1.1']
			});
			const timer = setTimeout(() => {
				socket.destroy();
				reject(new Error('目标 TLS 握手超时'));
			}, CHECK_TIMEOUT_MS);

			socket.once('secureConnect', () => {
				clearTimeout(timer);
				socket.on('error', () => { });
				resolve(socket);
			});
			socket.once('error', error => {
				clearTimeout(timer);
				reject(new Error(`目标 TLS 握手失败: ${error.message}`));
			});
		});

		try {
			secure.write(Buffer.from(
				`GET ${TARGET_PATH} HTTP/1.1\r\n`
				+ `Host: ${TARGET_HOST}\r\n`
				+ 'User-Agent: Mozilla/5.0 CF-Workers-CheckProxy/2.0\r\n'
				+ 'Accept: application/json\r\n'
				+ 'Connection: close\r\n\r\n',
				'latin1'
			));

			const reader = new ByteReader(secure, { timeoutMs: READ_TIMEOUT_MS });
			const body = await readHttpResponse(reader);

			let exit;
			try {
				exit = JSON.parse(body.toString('utf8').trim());
			} catch {
				throw new Error('目标站点未返回合法 JSON');
			}

			return buildCheckResult({
				type,
				rawValue: value,
				proxy,
				success: true,
				exit: normalizeExit(exit),
				responseTime: Date.now() - startedAt
			});
		} finally {
			try {
				secure.destroy();
			} catch { /* 忽略 */ }
		}
	} catch (error) {
		return buildCheckResult({
			type,
			rawValue: value,
			proxy,
			success: false,
			error: error?.message || String(error),
			responseTime: Date.now() - startedAt
		});
	} finally {
		try {
			tunnel?.destroy?.();
		} catch { /* 忽略 */ }
	}
}

export const TARGET = { host: TARGET_HOST, port: TARGET_PORT, path: TARGET_PATH };
