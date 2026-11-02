import http from 'node:http';
import os from 'node:os';
import { checkProxy, TARGET } from './check.js';
import { PROXY_TYPES, DEFAULT_PORTS, splitProxyScheme, parseProxyAddress, stripProxyScheme } from './parse.js';

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '0.0.0.0';
const TOKEN = process.env.PROBE_TOKEN || '';
const BATCH_LIMIT = Number(process.env.BATCH_LIMIT || 200);
const CONCURRENCY = Number(process.env.CONCURRENCY || 20);
const STARTED_AT = Date.now();

const CORS_HEADERS = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type, Authorization',
	'Access-Control-Max-Age': '86400'
};

function sendJson(res, data, status = 200, pretty = false) {
	const body = JSON.stringify(data, null, pretty ? 2 : 0);
	res.writeHead(status, {
		...CORS_HEADERS,
		'Content-Type': 'application/json; charset=UTF-8',
		'Cache-Control': 'no-cache, no-store, must-revalidate',
		'Content-Length': Buffer.byteLength(body)
	});
	res.end(body);
}

function isAuthorized(req, url) {
	if (!TOKEN) return true;
	const header = req.headers.authorization || '';
	if (header === `Bearer ${TOKEN}`) return true;
	return url.searchParams.get('token') === TOKEN;
}

/** 从查询参数或路径里解析出 { type, value }，与 _worker.js:137-171 的参数形态保持一致 */
function resolveCheckParams(url) {
	for (const type of PROXY_TYPES) {
		if (url.searchParams.has(type)) return { type, value: url.searchParams.get(type) || '' };
	}

	if (url.searchParams.has('proxy')) {
		const parsed = splitProxyScheme(url.searchParams.get('proxy') || '');
		if (parsed) return { type: parsed.type, value: parsed.rest };
	}

	const tail = decodeURIComponent(url.pathname.slice('/check'.length).replace(/^\/+/, ''));
	const match = tail.match(/^(socks5|http|https|sstp|proxy)=(.+)$/i);
	if (!match) return null;

	const key = match[1].toLowerCase();
	if (key === 'proxy') {
		const parsed = splitProxyScheme(match[2]);
		return parsed ? { type: parsed.type, value: parsed.rest } : null;
	}
	return { type: key, value: match[2] };
}

/** 批量输入：既接受 "sstp://user:pass@host:port#备注"，也接受裸 "host:port"（用 fallbackType 补类型） */
function normalizeTarget(input, fallbackType = 'socks5') {
	const text = String(input || '').trim();
	if (!text) return null;
	const parsed = splitProxyScheme(text);
	if (parsed) return { type: parsed.type, value: parsed.rest, raw: text };
	return { type: fallbackType, value: text, raw: text };
}

async function mapPool(items, limit, worker) {
	const results = new Array(items.length);
	let cursor = 0;

	const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
		for (;;) {
			const index = cursor++;
			if (index >= items.length) return;
			results[index] = await worker(items[index], index);
		}
	});

	await Promise.all(runners);
	return results;
}

async function readBody(req) {
	const chunks = [];
	let size = 0;
	for await (const chunk of req) {
		size += chunk.length;
		if (size > 4 * 1024 * 1024) throw new Error('请求体过大');
		chunks.push(chunk);
	}
	return Buffer.concat(chunks).toString('utf8');
}

async function handleBatch(req, res, url) {
	let payload;
	try {
		payload = JSON.parse(await readBody(req) || '{}');
	} catch (error) {
		return sendJson(res, { success: false, error: `请求体不是合法 JSON: ${error.message}` }, 400);
	}

	const rawTargets = Array.isArray(payload?.targets)
		? payload.targets
		: Array.isArray(payload?.proxies) ? payload.proxies : null;

	if (!rawTargets?.length) {
		return sendJson(res, { success: false, error: '缺少 targets 数组' }, 400);
	}

	const fallbackType = PROXY_TYPES.includes(payload?.type) ? payload.type : 'socks5';
	const targets = rawTargets.map(item => normalizeTarget(item, fallbackType)).filter(Boolean);

	if (targets.length > BATCH_LIMIT) {
		return sendJson(res, { success: false, error: `单次批量上限为 ${BATCH_LIMIT} 个` }, 400);
	}

	const startedAt = Date.now();
	const results = await mapPool(targets, CONCURRENCY, async target => {
		const result = await checkProxy({ type: target.type, value: target.value }, DEFAULT_PORTS[target.type]);
		return { ...result, input: target.raw };
	});

	const okCount = results.filter(item => item.success).length;
	const total = results.length;
	const average = total ? Math.round(results.reduce((sum, item) => sum + item.responseTime, 0) / total) : 0;

	return sendJson(res, {
		success: true,
		total,
		alive: okCount,
		dead: total - okCount,
		averageResponseTime: average,
		elapsed: Date.now() - startedAt,
		target: TARGET,
		results
	});
}

const server = http.createServer(async (req, res) => {
	const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

	if (req.method === 'OPTIONS') {
		res.writeHead(204, CORS_HEADERS);
		return res.end();
	}

	try {
		if (!isAuthorized(req, url)) {
			return sendJson(res, { success: false, error: '未授权：请提供 Authorization: Bearer <TOKEN>' }, 401);
		}

		const pathname = url.pathname.toLowerCase();

		if (pathname === '/' || pathname === '/index') {
			return sendJson(res, {
				service: 'probe-api',
				version: '1.0.0',
				target: TARGET,
				types: PROXY_TYPES,
				defaultPorts: DEFAULT_PORTS,
				endpoints: {
					'GET /check?socks5=host:port': '单个探测（支持 ?http= / ?https= / ?sstp= / ?proxy=socks5://host:port）',
					'GET /check/sstp=host:port': '路径形式，便于直接拼链接',
					'POST /check/batch': '{"targets":["sstp://vpn:vpn@1.2.3.4:443#日本"],"type":"socks5"}',
					'GET /health': '健康检查',
					'GET /ip.json': '查看服务自身出口信息'
				},
				limits: { BATCH_LIMIT, CONCURRENCY },
				uptime: Math.round((Date.now() - STARTED_AT) / 1000)
			}, 200, true);
		}

		if (pathname === '/health') {
			return sendJson(res, {
				ok: true,
				uptime: Math.round((Date.now() - STARTED_AT) / 1000),
				pid: process.pid,
				node: process.version,
				hostname: os.hostname(),
				load: os.loadavg()[0]
			});
		}

		if (pathname === '/ip.json') {
			const forwarded = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
			return sendJson(res, {
				ip: forwarded || req.socket.remoteAddress,
				server: os.hostname(),
				time: new Date().toISOString()
			}, 200, true);
		}

		if (pathname === '/check/batch' || pathname === '/check-batch') {
			if (req.method !== 'POST') {
				res.setHeader('Allow', 'POST, OPTIONS');
				return sendJson(res, { success: false, error: '批量探测请使用 POST' }, 405);
			}
			return await handleBatch(req, res, url);
		}

		if (pathname.startsWith('/check')) {
			// 同时支持 POST /check {"type":"sstp","value":"..."}
			if (req.method === 'POST' && pathname === '/check') {
				let payload;
				try {
					payload = JSON.parse(await readBody(req) || '{}');
				} catch (error) {
					return sendJson(res, { success: false, error: `请求体不是合法 JSON: ${error.message}` }, 400);
				}
				if (!PROXY_TYPES.includes(payload?.type)) {
					return sendJson(res, { success: false, error: `type 必须是 ${PROXY_TYPES.join(' / ')}` }, 400);
				}
				const result = await checkProxy({ type: payload.type, value: String(payload.value || '') }, DEFAULT_PORTS[payload.type]);
				return sendJson(res, result, 200, url.searchParams.has('pretty'));
			}

			const params = resolveCheckParams(url);
			if (!params) {
				return sendJson(res, {
					success: false,
					error: '缺少代理参数。用法：/check?socks5=host:port、/check?sstp=host:port、/check?proxy=socks5://host:port'
				}, 400);
			}

			const result = await checkProxy(params, DEFAULT_PORTS[params.type]);
			return sendJson(res, result, 200, url.searchParams.has('pretty'));
		}

		return sendJson(res, { success: false, error: '未找到该接口' }, 404);
	} catch (error) {
		return sendJson(res, { success: false, error: error?.message || String(error) }, 500);
	}
});

server.headersTimeout = 30_000;
server.requestTimeout = 120_000;
server.keepAliveTimeout = 15_000;

server.listen(PORT, HOST, () => {
	console.log(`[probe-api] listening on http://${HOST}:${PORT}`);
	console.log(`[probe-api] 探测目标 ${TARGET.host}:${TARGET.port}${TARGET.path}`);
	console.log(`[probe-api] 鉴权 ${TOKEN ? '已开启（Bearer Token）' : '未开启（PROBE_TOKEN 为空）'}，批量上限 ${BATCH_LIMIT}，并发 ${CONCURRENCY}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
	process.on(signal, () => {
		console.log(`[probe-api] 收到 ${signal}，正在关闭...`);
		server.close(() => process.exit(0));
		setTimeout(() => process.exit(0), 5000).unref();
	});
}

process.on('unhandledRejection', error => {
	console.error('[probe-api] 未处理的 Promise 拒绝:', error);
});
process.on('uncaughtException', error => {
	console.error('[probe-api] 未捕获异常:', error);
});

export { server, stripProxyScheme, parseProxyAddress };
