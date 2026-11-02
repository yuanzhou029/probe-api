import tls from 'node:tls';
import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import { Duplex } from 'node:stream';
import { ByteReader, concatBytes, withTimeout } from './util.js';
import { stripIPv6Brackets, isIPv4 } from './parse.js';
import { CONNECT_TIMEOUT_MS } from './config.js';

// SSTP = TLS 上承载 SSTP 控制报文 + PPP 会话，PPP 里再跑 IP，IP 里再跑我们手工合成的 TCP。
// 这条链路在 _worker.js:953-1538 里已完整实现，这里是它的 Node 版本：
// 唯一的变化是 TLS 交给 Node 原生 tls 模块，其余报文格式逐字节保持一致。

const SSTP_TCP_MSS = 1400;
const EMPTY = Buffer.alloc(0);

const PPP_PROTO_IP = 0x0021;
const PPP_PROTO_LCP = 0xc021;
const PPP_PROTO_PAP = 0xc023;
const PPP_PROTO_IPCP = 0x8021;

function internetChecksum(buffer, offset, length) {
	let sum = 0;
	let index = offset;
	for (; index < offset + length - 1; index += 2) {
		sum += (buffer[index] << 8) | buffer[index + 1];
	}
	if (length & 1) sum += buffer[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

function ipv4ToBuffer(ip) {
	return Buffer.from(String(ip).split('.').map(Number));
}

function formatHostHeader(hostname, port) {
	const host = stripIPv6Brackets(hostname);
	const display = host.includes(':') ? `[${host}]` : host;
	return Number(port) === 443 ? display : `${display}:${port}`;
}

async function resolveTargetIPv4(targetHost) {
	const host = stripIPv6Brackets(targetHost);
	if (isIPv4(host)) return host;
	const records = await dns.resolve4(host);
	if (!records?.length) throw new Error(`无法解析 ${targetHost} 的 IPv4 地址（SSTP 只支持 IPv4 目标）`);
	return records[0];
}

/** 默认拨号：SSTP 服务器一律走 TLS（自签证书普遍存在，故不校验证书，与 worker 行为一致） */
async function dialSstpTls(host, port, servername) {
	const raw = tls.connect({
		host,
		port,
		servername,
		rejectUnauthorized: false,
		ALPNProtocols: ['http/1.1']
	});
	raw.on('error', () => { });

	await new Promise((resolve, reject) => {
		const timer = setTimeout(() => {
			raw.destroy();
			reject(new Error('SSTP 服务器 TLS 握手超时'));
		}, CONNECT_TIMEOUT_MS);
		raw.once('secureConnect', () => {
			clearTimeout(timer);
			resolve();
		});
		raw.once('error', error => {
			clearTimeout(timer);
			reject(new Error(`SSTP 服务器 TLS 握手失败: ${error.message}`));
		});
	});

	return raw;
}

export class SstpClient {
	constructor(proxy, { dial } = {}) {
		this.proxy = proxy;
		this.dial = dial || dialSstpTls;
		this.socket = null;
		this.reader = null;
		this.serverHost = '';
		this.serverPort = 443;
		this.pppIdentifier = 1;
	}

	async connect() {
		this.serverHost = stripIPv6Brackets(this.proxy.hostname);
		this.serverPort = this.proxy.port;

		const socket = await this.dial(this.serverHost, this.serverPort, isIPv4(this.serverHost) ? undefined : this.serverHost);
		this.socket = socket;
		this.reader = new ByteReader(socket, { timeoutMs: CONNECT_TIMEOUT_MS });
	}

	write(buffer) {
		return new Promise((resolve, reject) => {
			this.socket.write(buffer, error => (error ? reject(error) : resolve()));
		});
	}

	static buildControlPacket(messageType, attributes = []) {
		const attributesLength = attributes.reduce((size, attribute) => size + 4 + attribute.data.length, 0);
		const packet = Buffer.alloc(8 + attributesLength);
		packet[0] = 0x10;
		packet[1] = 0x01;
		packet.writeUInt16BE((8 + attributesLength) | 0x8000, 2);
		packet.writeUInt16BE(messageType, 4);
		packet.writeUInt16BE(attributes.length, 6);

		let offset = 8;
		for (const attribute of attributes) {
			packet[offset + 1] = attribute.id;
			packet.writeUInt16BE(4 + attribute.data.length, offset + 2);
			attribute.data.copy(packet, offset + 4);
			offset += 4 + attribute.data.length;
		}
		return packet;
	}

	static buildDataPacket(pppFrame) {
		const length = 6 + pppFrame.length;
		const packet = Buffer.alloc(length);
		packet.set([0x10, 0x00, ((length >> 8) & 0x0f) | 0x80, length & 0xff, 0xff, 0x03]);
		pppFrame.copy(packet, 6);
		return packet;
	}

	static buildPppConfigurePacket(protocol, code, id, options = []) {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.length, 0);
		const frame = Buffer.alloc(6 + optionsLength);
		frame.writeUInt16BE(protocol, 0);
		frame[2] = code;
		frame[3] = id;
		frame.writeUInt16BE(4 + optionsLength, 4);

		let offset = 6;
		for (const option of options) {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.length;
			option.data.copy(frame, offset + 2);
			offset += 2 + option.data.length;
		}
		return frame;
	}

	buildPapRequest(id) {
		const { username, password } = this.proxy;
		if (username === null || password === null) throw new Error('SSTP 服务器要求 PAP 认证，但未提供账号密码');
		const user = Buffer.from(username, 'utf8');
		const pass = Buffer.from(password, 'utf8');
		if (user.length > 255 || pass.length > 255) throw new Error('SSTP 用户名或密码过长');

		const papLength = 6 + user.length + pass.length;
		const frame = Buffer.alloc(2 + papLength);
		frame.writeUInt16BE(PPP_PROTO_PAP, 0);
		frame[2] = 1;
		frame[3] = id;
		frame.writeUInt16BE(papLength, 4);
		frame[6] = user.length;
		user.copy(frame, 7);
		frame[7 + user.length] = pass.length;
		pass.copy(frame, 8 + user.length);
		return frame;
	}

	async readPacket(timeoutMs = CONNECT_TIMEOUT_MS) {
		const header = await withTimeout(this.reader.readExactly(4), timeoutMs, 'SSTP 读取超时');
		const length = header.readUInt16BE(2) & 0x0fff;
		if (length < 4) throw new Error('SSTP 报文长度非法');
		const body = length > 4
			? await withTimeout(this.reader.readExactly(length - 4), timeoutMs, 'SSTP 报文体读取超时')
			: EMPTY;
		return { isControl: (header[1] & 1) !== 0, body };
	}

	static parsePppFrame(data) {
		const offset = data.length >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.length - offset < 4) return null;

		const protocol = data.readUInt16BE(offset);
		if (protocol === PPP_PROTO_IP) {
			return { protocol, ipPacket: data.subarray(offset + 2) };
		}
		if (data.length - offset < 6) return null;
		return {
			protocol,
			code: data[offset + 2],
			id: data[offset + 3],
			payload: data.subarray(offset + 6),
			rawPacket: data.subarray(offset)
		};
	}

	static parsePppOptions(data) {
		const options = [];
		let offset = 0;
		while (offset + 2 <= data.length) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.length) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	}

	async establishTunnel() {
		const httpRequest = Buffer.from(
			'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n'
			+ `Host: ${formatHostHeader(this.serverHost, this.serverPort)}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`,
			'latin1'
		);
		const encapsulatedProtocol = Buffer.alloc(2);
		encapsulatedProtocol.writeUInt16BE(1, 0); // 1 = PPP
		const maximumReceiveUnit = Buffer.alloc(2);
		maximumReceiveUnit.writeUInt16BE(1500, 0);

		await withTimeout(this.write(concatBytes(
			httpRequest,
			SstpClient.buildControlPacket(0x0001, [{ id: 1, data: encapsulatedProtocol }]),
			SstpClient.buildDataPacket(SstpClient.buildPppConfigurePacket(PPP_PROTO_LCP, 1, this.pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP 握手写入超时');

		const headerBlock = (await withTimeout(
			this.reader.readUntil('\r\n\r\n'),
			CONNECT_TIMEOUT_MS,
			'SSTP HTTP 握手响应超时'
		)).toString('latin1');
		const statusLine = headerBlock.split('\r\n')[0] || '';
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) {
			throw new Error(`SSTP HTTP 握手失败: ${statusLine || '无效状态行'}`);
		}

		let sstpAccepted = false;
		let localLcpAcked = false;
		let peerLcpAcked = false;
		let papRequired = false;
		let papSent = false;
		let papDone = false;
		let ipcpStarted = false;
		let ipcpFinished = false;
		let assignedIp = null;

		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			await withTimeout(
				this.write(SstpClient.buildDataPacket(this.buildPapRequest(this.pppIdentifier++))),
				CONNECT_TIMEOUT_MS,
				'SSTP PAP 认证请求超时'
			);
			papSent = true;
		};

		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(
				this.write(SstpClient.buildDataPacket(SstpClient.buildPppConfigurePacket(PPP_PROTO_IPCP, 1, this.pppIdentifier++, [
					{ type: 3, data: Buffer.alloc(4) }
				]))),
				CONNECT_TIMEOUT_MS,
				'SSTP IPCP 请求超时'
			);
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await this.readPacket(CONNECT_TIMEOUT_MS);

			if (packet.isControl) {
				// 0x0002 = Call Connected，收到即表示 SSTP 层已建立
				if (!sstpAccepted && packet.body.length >= 2 && packet.body.readUInt16BE(0) === 2) sstpAccepted = true;
				continue;
			}

			const ppp = SstpClient.parsePppFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === PPP_PROTO_LCP) {
				if (ppp.code === 1) {
					const authOption = SstpClient.parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.length >= 2) {
						const authProtocol = authOption.data.readUInt16BE(0);
						if (authProtocol !== PPP_PROTO_PAP) {
							throw new Error(`SSTP 不支持该 PPP 认证协议: 0x${authProtocol.toString(16)}`);
						}
						papRequired = true;
					}
					const ack = Buffer.from(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(this.write(SstpClient.buildDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack 超时');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === PPP_PROTO_PAP) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					throw new Error('SSTP PAP 认证失败（账号或密码错误）');
				}
				continue;
			}

			if (ppp.protocol === PPP_PROTO_IPCP) {
				if (ppp.code === 1) {
					const ack = Buffer.from(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(this.write(SstpClient.buildDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack 超时');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = SstpClient.parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.length === 4) {
						assignedIp = [...addressOption.data].join('.');
						await withTimeout(
							this.write(SstpClient.buildDataPacket(SstpClient.buildPppConfigurePacket(PPP_PROTO_IPCP, 1, this.pppIdentifier++, [
								{ type: 3, data: addressOption.data }
							]))),
							CONNECT_TIMEOUT_MS,
							'SSTP IPCP 地址请求超时'
						);
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = SstpClient.parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.length === 4) assignedIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}

		if (!assignedIp) throw new Error('SSTP 未分配到 IPv4 地址');
		return assignedIp;
	}

	close() {
		try {
			this.reader?.detach?.();
		} catch { /* 忽略 */ }
		try {
			this.socket?.destroy?.();
		} catch { /* 忽略 */ }
	}
}

class TcpOverPpp {
	constructor(client, sourceIp, destinationIp, destinationPort) {
		this.client = client;
		this.sourcePort = 10000 + (crypto.randomInt(0, 50000));
		this.sourceAddress = ipv4ToBuffer(sourceIp);
		this.destinationAddress = ipv4ToBuffer(destinationIp);
		this.destinationPort = destinationPort;

		this.sequenceNumber = crypto.randomInt(0, 0xffffffff) >>> 0;
		this.acknowledgementNumber = 0;

		this.ipHeaderTemplate = Buffer.alloc(20);
		this.ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		this.sourceAddress.copy(this.ipHeaderTemplate, 12);
		this.destinationAddress.copy(this.ipHeaderTemplate, 16);

		this.pseudoHeader = Buffer.alloc(1432);
		this.sourceAddress.copy(this.pseudoHeader, 0);
		this.destinationAddress.copy(this.pseudoHeader, 4);
		this.pseudoHeader[9] = 6;
	}

	buildFrame(flags, payload = EMPTY) {
		const payloadLength = payload.length;
		const tcpLength = 20 + payloadLength;
		const ipLength = 20 + tcpLength;
		const sstpLength = 8 + ipLength;
		const frame = Buffer.alloc(sstpLength);

		frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
		this.ipHeaderTemplate.copy(frame, 8);
		frame.writeUInt16BE(ipLength, 10);
		frame.writeUInt16BE(crypto.randomInt(0, 0xffff), 12);
		frame.writeUInt16BE(internetChecksum(frame, 8, 20), 18);

		frame.writeUInt16BE(this.sourcePort, 28);
		frame.writeUInt16BE(this.destinationPort, 30);
		frame.writeUInt32BE(this.sequenceNumber, 32);
		frame.writeUInt32BE(this.acknowledgementNumber, 36);
		frame[40] = 0x50;
		frame[41] = flags;
		frame.writeUInt16BE(65535, 42);
		if (payloadLength) payload.copy(frame, 48);

		this.pseudoHeader[10] = tcpLength >> 8;
		this.pseudoHeader[11] = tcpLength & 0xff;
		frame.copy(this.pseudoHeader, 12, 28, 28 + tcpLength);
		frame.writeUInt16BE(internetChecksum(this.pseudoHeader, 0, 12 + tcpLength), 44);
		return frame;
	}

	matchIncoming(ipPacket) {
		if (ipPacket.length < 40 || ipPacket[9] !== 6) return null;
		const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
		if (ipPacket.length < ipHeaderLength + 20) return null;
		if (ipPacket.readUInt16BE(ipHeaderLength) !== this.destinationPort) return null;
		if (ipPacket.readUInt16BE(ipHeaderLength + 2) !== this.sourcePort) return null;
		return {
			flags: ipPacket[ipHeaderLength + 13],
			sequence: ipPacket.readUInt32BE(ipHeaderLength + 4),
			payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
		};
	}

	async handshake() {
		await withTimeout(this.client.write(this.buildFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN 写入超时');
		this.sequenceNumber = (this.sequenceNumber + 1) >>> 0;

		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await this.client.readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;

			const ppp = SstpClient.parsePppFrame(packet.body);
			if (!ppp || ppp.protocol !== PPP_PROTO_IP) continue;

			const incoming = this.matchIncoming(ppp.ipPacket);
			if (!incoming || (incoming.flags & 0x12) !== 0x12) continue;

			this.acknowledgementNumber = (incoming.sequence + 1) >>> 0;
			await withTimeout(this.client.write(this.buildFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK 写入超时');
			return;
		}
		throw new Error('SSTP 隧道内 TCP 握手超时');
	}
}

/** 把 SSTP 里的合成 TCP 会话包装成 Node 双工流，可直接交给 tls.connect({ socket }) */
class SstpTunnel extends Duplex {
	constructor(client, tcp) {
		super();
		this.client = client;
		this.tcp = tcp;
		this._loop().catch(error => this.destroy(error));
	}

	async _loop() {
		for (;;) {
			const packet = await this.client.readPacket(60000);
			if (packet.isControl) continue;

			const ppp = SstpClient.parsePppFrame(packet.body);
			if (!ppp || ppp.protocol !== PPP_PROTO_IP) continue;

			const incoming = this.tcp.matchIncoming(ppp.ipPacket);
			if (!incoming) continue;

			if (incoming.payloadOffset < ppp.ipPacket.length) {
				const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
				if (payload.length) {
					this.tcp.acknowledgementNumber = (incoming.sequence + payload.length) >>> 0;
					this.push(Buffer.from(payload));
				}
			}

			if (incoming.flags & 0x01) { // FIN
				this.client.write(this.tcp.buildFrame(0x11)).catch(() => { });
				this.push(null);
				this.client.close();
				return;
			}

			this.client.write(this.tcp.buildFrame(0x10)).catch(() => { });
		}
	}

	_read() {
		// 数据由 _loop 主动 push，无需额外处理
	}

	_write(chunk, encoding, callback) {
		try {
			const bytes = Buffer.from(chunk);
			if (!bytes.length) return callback();

			const frames = [];
			for (let offset = 0; offset < bytes.length; offset += SSTP_TCP_MSS) {
				const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.length));
				frames.push(this.tcp.buildFrame(0x18, segment));
				this.tcp.sequenceNumber = (this.tcp.sequenceNumber + segment.length) >>> 0;
			}
			this.client.write(concatBytes(...frames)).then(() => callback(), callback);
		} catch (error) {
			callback(error);
		}
	}

	_destroy(error, callback) {
		try {
			this.client.write(this.tcp.buildFrame(0x11)).catch(() => { });
		} catch { /* 忽略 */ }
		this.client.close();
		callback(error);
	}
}

export async function sstpConnect(proxy, targetHost, targetPort, options = {}) {
	const client = new SstpClient(proxy, options);
	try {
		await client.connect();
		const targetIpPromise = resolveTargetIPv4(targetHost);
		const [sourceIp, targetIp] = await Promise.all([client.establishTunnel(), targetIpPromise]);

		const tcp = new TcpOverPpp(client, sourceIp, targetIp, targetPort);
		await tcp.handshake();
		return new SstpTunnel(client, tcp);
	} catch (error) {
		client.close();
		throw error;
	}
}
