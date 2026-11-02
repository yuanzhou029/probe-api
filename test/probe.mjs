// 直接调用探测核心（不经过 HTTP），用于在 VPS 上快速验证链路是否通。
// 用法：node test/probe.mjs sstp://vpn:vpn@1.2.3.4:443
import { checkProxy } from '../src/check.js';
import { splitProxyScheme, DEFAULT_PORTS } from '../src/parse.js';

const targets = process.argv.slice(2);
if (!targets.length) {
	console.log('用法: node test/probe.mjs <sstp://user:pass@host:443> [更多目标...]');
	process.exit(1);
}

for (const target of targets) {
	const started = Date.now();
	const parsed = splitProxyScheme(target) || { type: 'socks5', rest: target };
	const result = await checkProxy({ type: parsed.type, value: parsed.rest }, DEFAULT_PORTS[parsed.type]);
	console.log(JSON.stringify({
		target,
		success: result.success,
		responseTime: result.responseTime,
		error: result.error,
		exitIp: result.exit?.ip,
		country: result.exit?.country,
		org: result.exit?.asn?.name
	}, null, 2));
	console.log(`实际耗时 ${Date.now() - started}ms\n`);
}

process.exit(0);
