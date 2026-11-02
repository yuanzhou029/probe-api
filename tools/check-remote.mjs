#!/usr/bin/env node
// 远程调用 probe-api 做批量存活体检：拉源 → 分片 POST /check/batch → 打印结果。
// 只依赖 Node 18+ 自带的 fetch，不引入第三方包。
//
// 用法：
//   node tools/check-remote.mjs --source https://example.com/nodes.txt
//   node tools/check-remote.mjs --source ./nodes.txt --out alive.txt
//   node tools/check-remote.mjs socks5://u:p@1.2.3.4:1080 5.6.7.8:8080
//
// 环境变量：
//   PROBE_API          API 基地址，默认 http://127.0.0.1:8787
//   PROBE_API_TOKEN    鉴权 token（必填）
//   PROBE_SOURCE       默认数据源，可用 --source 覆盖

const DEFAULT_SOURCE = 'https://gx.51281868.xyz/SSTP.txt?token=yuanzhou029';
const SCHEMES = ['socks5', 'socks5h', 'http', 'https', 'sstp'];

function parseArgs(argv) {
	const opts = { targets: [], source: process.env.PROBE_SOURCE || DEFAULT_SOURCE, api: process.env.PROBE_API || 'http://127.0.0.1:8787', token: process.env.PROBE_API_TOKEN || '', chunk: 50, out: '', json: '', timeout: 120000 };
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		const next = () => argv[++i];
		if (arg === '--source') opts.source = next();
		else if (arg === '--api') opts.api = next();
		else if (arg === '--token') opts.token = next();
		else if (arg === '--chunk') opts.chunk = Math.max(1, Number(next()) || 50);
		else if (arg === '--out') opts.out = next();
		else if (arg === '--json') opts.json = next();
		else if (arg === '--timeout') opts.timeout = Math.max(1000, Number(next()) || 120000);
		else if (arg === '--help' || arg === '-h') opts.help = true;
		else if (arg.startsWith('--')) throw new Error(`未知参数: ${arg}`);
		else opts.targets.push(arg);
	}
	return opts;
}

const USAGE = `用法:
  node tools/check-remote.mjs --source <URL或文件> [--chunk 50] [--out alive.txt] [--json raw.json]
  node tools/check-remote.mjs socks5://user:pass@1.2.3.4:1080 5.6.7.8:8080

环境变量:
  PROBE_API         API 基地址（默认 http://127.0.0.1:8787）
  PROBE_API_TOKEN   鉴权 token（必填，或用 --token）
  PROBE_SOURCE      默认数据源（可用 --source 覆盖）

退出码: 0 正常完成 / 1 参数或网络错误 / 2 鉴权失败`;

function looksLikeNode(line) {
	if (!line || line.startsWith('#') || line.startsWith('//')) return false;
	const lower = line.toLowerCase();
	if (SCHEMES.some(scheme => lower.startsWith(`${scheme}://`))) return true;
	return /^(\[[0-9a-f:]+\]|[^\s:/]+):\d{1,5}/i.test(line);
}

/** 订阅源可能是明文列表，也可能是 base64 整包，两种都解 */
function parseSource(text) {
	let body = text.trim();
	if (!body.includes('://') && /^[A-Za-z0-9+/=\s]+$/.test(body)) {
		try {
			const decoded = Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8');
			if (decoded.includes('://')) body = decoded;
		} catch { /* 不是 base64 就按原样处理 */ }
	}
	return body.split(/\r?\n/).map(line => line.trim()).filter(looksLikeNode);
}

async function loadTargets(opts) {
	if (opts.targets.length) return { targets: opts.targets, from: '命令行参数' };
	const isUrl = /^https?:\/\//i.test(opts.source);
	const text = isUrl
		? await (async () => {
			const response = await fetch(opts.source, { signal: AbortSignal.timeout(opts.timeout) });
			if (!response.ok) throw new Error(`拉取数据源失败: HTTP ${response.status}`);
			return response.text();
		})()
		: await (await import('node:fs/promises')).readFile(opts.source, 'utf8');
	const targets = parseSource(text);
	if (!targets.length) throw new Error(`数据源里没解析出任何节点: ${opts.source}`);
	return { targets, from: opts.source };
}

async function callBatch(opts, chunk, index, total) {
	const url = new URL('/check/batch', opts.api);
	const response = await fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${opts.token}` },
		body: JSON.stringify({ targets: chunk }),
		signal: AbortSignal.timeout(opts.timeout)
	});
	const text = await response.text();
	let payload;
	try {
		payload = JSON.parse(text);
	} catch {
		throw new Error(`接口返回的不是 JSON（HTTP ${response.status}）: ${text.slice(0, 200)}`);
	}
	if (response.status === 401) {
		const error = new Error(`鉴权失败: ${payload.error || '请检查 PROBE_API_TOKEN'}`);
		error.code = 2;
		throw error;
	}
	if (!response.ok) throw new Error(`批量接口报错（HTTP ${response.status}）: ${payload.error || text.slice(0, 200)}`);
	process.stderr.write(`\r  已探测 ${Math.min(index + chunk.length, total)}/${total} 个…`);
	return payload;
}

function displayWidth(text) {
	// 中文按两列宽估算，避免表格错位
	return [...String(text ?? '')].reduce((sum, ch) => sum + (/[\u4e00-\u9fff]/.test(ch) ? 2 : 1), 0);
}

function pad(value, width) {
	const text = String(value ?? '');
	return text + ' '.repeat(Math.max(1, width - displayWidth(text)));
}

async function main() {
	const opts = parseArgs(process.argv.slice(2));
	if (opts.help) return void console.log(USAGE);
	if (!opts.token) {
		console.error('缺少 token：设置环境变量 PROBE_API_TOKEN，或用 --token 传入');
		console.error(USAGE);
		process.exitCode = 1;
		return;
	}

	const { targets, from } = await loadTargets(opts);
	console.log(`数据源：${from}`);
	console.log(`API：${opts.api}`);
	console.log(`候选：${targets.length} 个，每批 ${opts.chunk} 个\n`);

	const all = [];
	const startedAt = Date.now();
	for (let i = 0; i < targets.length; i += opts.chunk) {
		const payload = await callBatch(opts, targets.slice(i, i + opts.chunk), i, targets.length);
		all.push(...payload.results);
	}
	process.stderr.write('\r' + ' '.repeat(40) + '\r');

	const alive = all.filter(item => item.success);
	const rows = [...all]
		.sort((a, b) => (a.success === b.success ? a.responseTime - b.responseTime : a.success ? -1 : 1))
		.map(item => ({
			status: item.success ? '✓ 活' : '✗ 死',
			latency: `${item.responseTime}ms`,
			type: item.type,
			node: `${item.hostname}:${item.port}${item.username ? ` (${item.username})` : ''}`,
			exit: item.exit?.ip || '-',
			error: item.success ? '' : (item.error || '')
		}));
	const widthOf = key => Math.max(displayWidth(key), ...rows.map(row => displayWidth(row[key]))) + 2;
	const [wStatus, wLatency, wType, wNode] = [widthOf('status'), widthOf('latency'), widthOf('type'), widthOf('node')];

	console.log(pad('状态', wStatus) + pad('延迟', wLatency) + pad('类型', wType) + pad('节点', wNode) + '出口');
	console.log('-'.repeat(wStatus + wLatency + wType + wNode + 18));
	for (const row of rows) {
		console.log(pad(row.status, wStatus) + pad(row.latency, wLatency) + pad(row.type, wType) + pad(row.node, wNode) + row.exit);
		if (row.error) console.log(pad('', wStatus) + `└ ${row.error}`);
	}

	const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
	console.log(`\n合计 ${all.length} 个：活 ${alive.length}，死 ${all.length - alive.length}，耗时 ${elapsed}s`);

	if (opts.out) {
		const { writeFile } = await import('node:fs/promises');
		const body = alive.map(item => item.input || item.link).join('\n') + '\n';
		await writeFile(opts.out, body, 'utf8');
		console.log(`存活清单已写入 ${opts.out}（${alive.length} 行）`);
	}
	if (opts.json) {
		const { writeFile } = await import('node:fs/promises');
		await writeFile(opts.json, JSON.stringify({ source: from, api: opts.api, results: all }, null, 2), 'utf8');
		console.log(`完整结果已写入 ${opts.json}`);
	}
}

main().catch(error => {
	console.error(`\n失败: ${error.message}`);
	process.exitCode = error.code === 2 ? 2 : 1;
});
