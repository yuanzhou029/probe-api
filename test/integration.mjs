// 集成自测：用本地 mock 代理验证四类隧道 + “真实 TLS 到目标站点”的整条链路。
// 运行：node test/integration.mjs
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { checkProxy } from '../src/check.js';
import { sstpConnect } from '../src/sstp.js';
import { startMockSstp } from './mock-sstp.mjs';

let failures = 0;
function report(name, ok, detail) {
	console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
	if (!ok) failures++;
}

function startMockSocks5() {
	const server = net.createServer(socket => {
		socket.on('error', () => { });
		let buffer = Buffer.alloc(0);
		let stage = 'greeting';

		const onData = chunk => {
			buffer = Buffer.concat([buffer, chunk]);

			if (stage === 'greeting') {
				if (buffer.length < 2) return;
				const methods = buffer[1];
				if (buffer.length < 2 + methods) return;
				buffer = buffer.subarray(2 + methods);
				socket.write(Buffer.from([0x05, 0x00]));
				stage = 'request';
			}

			if (stage !== 'request') return;
			if (buffer.length < 5) return;

			const atyp = buffer[3];
			const addressLength = atyp === 0x01 ? 4 : atyp === 0x04 ? 16 : buffer[4];
			const headerLength = atyp === 0x03 ? 5 + addressLength + 2 : 4 + addressLength + 2;
			if (buffer.length < headerLength) return;

			const host = atyp === 0x01
				? [...buffer.subarray(4, 8)].join('.')
				: atyp === 0x04
					? buffer.subarray(4, 20).toString('hex').replace(/(.{4})(?=.)/g, '$1:')
					: buffer.subarray(5, 5 + addressLength).toString();
			const port = buffer.readUInt16BE(headerLength - 2);
			const rest = buffer.subarray(headerLength);
			stage = 'piping';
			socket.removeListener('data', onData);

			const upstream = net.connect({ host, port }, () => {
				socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
				if (rest.length) upstream.write(rest);
				socket.pipe(upstream);
				upstream.pipe(socket);
			});
			upstream.on('error', () => socket.destroy());
		};

		socket.on('data', onData);
	});

	return new Promise(resolve => {
		server.listen(0, '127.0.0.1', () => resolve({
			port: server.address().port,
			close: () => new Promise(done => server.close(done))
		}));
	});
}

function startMockHttpProxy() {
	const server = net.createServer(socket => {
		socket.on('error', () => { });
		let buffer = Buffer.alloc(0);

		const onData = chunk => {
			buffer = Buffer.concat([buffer, chunk]);
			const headerEnd = buffer.indexOf('\r\n\r\n');
			if (headerEnd === -1) return;

			const headerText = buffer.subarray(0, headerEnd).toString('latin1');
			const match = headerText.match(/^CONNECT\s+([^\s:]+):(\d+)/i);
			const rest = buffer.subarray(headerEnd + 4);
			socket.removeListener('data', onData);

			if (!match) {
				socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
				return;
			}

			const upstream = net.connect({ host: match[1], port: Number(match[2]) }, () => {
				socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
				if (rest.length) upstream.write(rest);
				socket.pipe(upstream);
				upstream.pipe(socket);
			});
			upstream.on('error', () => socket.destroy());
		};

		socket.on('data', onData);
	});

	return new Promise(resolve => {
		server.listen(0, '127.0.0.1', () => resolve({
			port: server.address().port,
			close: () => new Promise(done => server.close(done))
		}));
	});
}

function readAll(socket, timeoutMs = 25000) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		const timer = setTimeout(() => reject(new Error('读取超时')), timeoutMs);
		socket.on('data', chunk => chunks.push(chunk));
		socket.on('end', () => {
			clearTimeout(timer);
			resolve(Buffer.concat(chunks).toString('utf8'));
		});
		socket.on('error', error => {
			clearTimeout(timer);
			reject(error);
		});
	});
}

const socksProxy = await startMockSocks5();
const httpProxy = await startMockHttpProxy();
const sstpServer = await startMockSstp({ log: process.env.DEBUG === '1' });

try {
	for (const [name, type, port] of [
		['SOCKS5 隧道', 'socks5', socksProxy.port],
		['HTTP CONNECT 隧道', 'http', httpProxy.port]
	]) {
		const result = await checkProxy({ type, value: `127.0.0.1:${port}` }, type === 'socks5' ? 1080 : 80);
		report(name, result.success === true && Boolean(result.exit?.ip), result.success ? `出口 IP ${result.exit.ip} / ${result.exit.country}` : result.error);
	}

	// SSTP：mock 服务端是明文 TCP，所以这里覆写 dial（生产环境默认走 TLS）
	const tunnel = await sstpConnect(
		{ type: 'sstp', username: 'vpn', password: 'vpn', hostname: '127.0.0.1', port: sstpServer.port },
		'www.iplocate.io',
		443,
		{ dial: (host, port) => Promise.resolve(net.connect({ host, port })) }
	);

	const secure = tls.connect({ socket: tunnel, servername: 'www.iplocate.io' });
	await once(secure, 'secureConnect');
	secure.write('GET /api/lookup HTTP/1.1\r\nHost: www.iplocate.io\r\nAccept: application/json\r\nConnection: close\r\n\r\n');
	const response = await readAll(secure);
	const body = response.slice(response.indexOf('\r\n\r\n') + 4);
	let exit = null;
	try {
		exit = JSON.parse(body);
	} catch { /* 留给断言 */ }
	report('SSTP 隧道（PPP + 合成 TCP + 目标 TLS）', response.startsWith('HTTP/1.1 200') && Boolean(exit?.ip), exit?.ip ? `出口 IP ${exit.ip} / ${exit.country}` : response.slice(0, 120));
	secure.destroy();
} catch (error) {
	report('集成测试', false, error.stack || error.message);
} finally {
	await socksProxy.close();
	await httpProxy.close();
	await sstpServer.close();
}

console.log(failures ? `\n${failures} 项失败` : '\n全部通过');
process.exit(failures ? 1 : 0);
