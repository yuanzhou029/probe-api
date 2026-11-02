// 测试用的 SSTP/PPP 服务端桩：终止 SSTP + PPP，并把 IP 层里的 TCP 会话
// 直接 NAT 到真实互联网目标。用于在没有可达 SSTP 节点时验证客户端的整条协议栈
// （SSTP 报文 → PPP 协商/PAP → 合成 IP/TCP → 上面跑真实 TLS）。
import net from 'node:net';
import crypto from 'node:crypto';
import { ByteReader, concatBytes } from '../src/util.js';

const PPP_IP = 0x0021;
const PPP_LCP = 0xc021;
const PPP_PAP = 0xc023;
const PPP_IPCP = 0x8021;

function buildControlPacket(messageType, attributes = []) {
	const attributesLength = attributes.reduce((size, item) => size + 4 + item.data.length, 0);
	const packet = Buffer.alloc(8 + attributesLength);
	packet[0] = 0x10;
	packet[1] = 0x01;
	packet.writeUInt16BE((8 + attributesLength) | 0x8000, 2);
	packet.writeUInt16BE(messageType, 4);
	packet.writeUInt16BE(attributes.length, 6);
	let offset = 8;
	for (const item of attributes) {
		packet[offset + 1] = item.id;
		packet.writeUInt16BE(4 + item.data.length, offset + 2);
		item.data.copy(packet, offset + 4);
		offset += 4 + item.data.length;
	}
	return packet;
}

function buildPpp(protocol, code, id, options = []) {
	const optionsLength = options.reduce((size, item) => size + 2 + item.data.length, 0);
	const frame = Buffer.alloc(6 + optionsLength);
	frame.writeUInt16BE(protocol, 0);
	frame[2] = code;
	frame[3] = id;
	frame.writeUInt16BE(4 + optionsLength, 4);
	let offset = 6;
	for (const item of options) {
		frame[offset] = item.type;
		frame[offset + 1] = 2 + item.data.length;
		item.data.copy(frame, offset + 2);
		offset += 2 + item.data.length;
	}
	return frame;
}

function wrapSstp(payload) {
	const length = 4 + payload.length;
	const packet = Buffer.alloc(length);
	packet.set([0x10, 0x00, ((length >> 8) & 0x0f) | 0x80, length & 0xff]);
	payload.copy(packet, 4);
	return packet;
}

// PPP 帧固定以 ff 03 开头，后面紧跟 2 字节协议号
function wrapSstpPpp(frame) {
	return wrapSstp(Buffer.concat([Buffer.from([0xff, 0x03]), frame]));
}

function wrapSstpIp(ip) {
	return wrapSstp(Buffer.concat([Buffer.from([0xff, 0x03, 0x00, 0x21]), ip]));
}

function buildIpTcp({ source, destination, sourcePort, destinationPort, seq, ack, flags, payload = Buffer.alloc(0) }) {
	const totalLength = 40 + payload.length;
	const packet = Buffer.alloc(totalLength);
	packet[0] = 0x45;
	packet.writeUInt16BE(totalLength, 2);
	packet.writeUInt16BE(crypto.randomInt(0, 0xffff), 4);
	packet[6] = 0x40;
	packet[8] = 64;
	packet[9] = 6;
	source.copy(packet, 12);
	destination.copy(packet, 16);

	packet.writeUInt16BE(sourcePort, 20);
	packet.writeUInt16BE(destinationPort, 22);
	packet.writeUInt32BE(seq >>> 0, 24);
	packet.writeUInt32BE(ack >>> 0, 28);
	packet[32] = 0x50;
	packet[33] = flags;
	packet.writeUInt16BE(65535, 34);
	payload.copy(packet, 40);
	return packet;
}

function parseIpTcp(ip) {
	if (ip.length < 40 || ip[9] !== 6) return null;
	const ihl = (ip[0] & 0x0f) * 4;
	const tcpOffset = ihl + ((ip[ihl + 12] >> 4) & 0x0f) * 4;
	return {
		source: ip.subarray(12, 16),
		destination: ip.subarray(16, 20),
		sourcePort: ip.readUInt16BE(ihl),
		destinationPort: ip.readUInt16BE(ihl + 2),
		seq: ip.readUInt32BE(ihl + 4),
		flags: ip[ihl + 13],
		payload: ip.subarray(tcpOffset)
	};
}

export function startMockSstp({ log = false } = {}) {
	const say = (...args) => { if (log) console.log('[mock-sstp]', ...args); };

	const server = net.createServer(socket => {
		socket.on('error', () => { });
		const reader = new ByteReader(socket, { timeoutMs: 20000 });

		(async () => {
			const request = (await reader.readUntil('\r\n\r\n')).toString('latin1');
			if (!request.startsWith('SSTP_DUPLEX_POST')) throw new Error('不是 SSTP 握手请求');
			say('收到 SSTP 握手请求');

			socket.write('HTTP/1.1 200\r\n\r\n');
			socket.write(buildControlPacket(2)); // CALL_CONNECT_ACK

			let sentOwnLcpCrq = false;
			const assignedIp = Buffer.from([10, 0, 0, 2]);
			let upstream = null;
			let upstreamReady = false;
			const pendingWrites = [];
			let peerSeq = 0;
			let ourSeq = crypto.randomInt(0, 0xffffffff) >>> 0;
			let synAcked = false;
			// 回包的地址/端口必须和客户端合成 TCP 的源地址/源端口一致，否则客户端会丢弃
			let peerAddress = Buffer.from([127, 0, 0, 1]);
			let peerPort = 40000;

			const sendIp = (flags, payload = Buffer.alloc(0), ack = peerSeq) => {
				const packet = buildIpTcp({
					source: assignedIp,
					destination: peerAddress,
					sourcePort: 443,
					destinationPort: peerPort,
					seq: ourSeq,
					ack,
					flags,
					payload
				});
				socket.write(wrapSstpIp(packet));
			};

			const flushPending = () => {
				while (pendingWrites.length) upstream.write(pendingWrites.shift());
			};

			for (;;) {
				const header = await reader.readExactly(4);
				const length = header.readUInt16BE(2) & 0x0fff;
				const body = length > 4 ? await reader.readExactly(length - 4) : Buffer.alloc(0);
				if (header[1] & 1) continue; // 控制报文，忽略

				const protocol = body.readUInt16BE(2);
				const rest = body.subarray(4); // 去掉 ff 03 + 协议号后的 PPP 报文（code/id/...）
				say(`收到 PPP protocol=0x${protocol.toString(16)} code=${rest[0]} len=${length}`);

				if (protocol === PPP_LCP) {
					const code = rest[0];
					if (code === 1) {
						const ack = Buffer.concat([body.subarray(2, 4), Buffer.from(rest)]);
						ack[2] = 2;
						socket.write(wrapSstpPpp(ack));
						if (!sentOwnLcpCrq) {
							sentOwnLcpCrq = true;
							const auth = Buffer.alloc(2);
							auth.writeUInt16BE(PPP_PAP, 0);
							socket.write(wrapSstpPpp(buildPpp(PPP_LCP, 1, 200, [{ type: 3, data: auth }])));
						}
					} else if (code === 2) {
						say('客户端已 ACK 我方 LCP');
					}
					continue;
				}

				if (protocol === PPP_PAP) {
					// 客户端发来 Authenticate-Request（code 1），回 Authenticate-Ack（code 2）
					socket.write(wrapSstpPpp(buildPpp(PPP_PAP, 2, rest[1])));
					say('PAP 认证通过');
					continue;
				}

				if (protocol === PPP_IPCP) {
					const code = rest[0];
					const id = rest[1];
					if (code === 1) {
						const address = rest.subarray(6, 10); // rest 已是去掉 6 字节 PPP 头之后
						if (address.equals(Buffer.alloc(4))) {
							socket.write(wrapSstpPpp(buildPpp(PPP_IPCP, 3, id, [{ type: 3, data: assignedIp }])));
						} else {
							socket.write(wrapSstpPpp(buildPpp(PPP_IPCP, 2, id, [{ type: 3, data: address }])));
						}
					}
					continue;
				}

				if (protocol !== PPP_IP) continue;

				const tcp = parseIpTcp(body.subarray(4));
				if (!tcp) continue;

				if (tcp.flags & 0x02 && !synAcked) { // SYN
					synAcked = true;
					peerSeq = (tcp.seq + 1) >>> 0;
					peerAddress = Buffer.from(tcp.source);
					peerPort = tcp.sourcePort;
					sendIp(0x12, Buffer.alloc(0), peerSeq); // SYN-ACK
					ourSeq = (ourSeq + 1) >>> 0;
					say('收到 SYN，回 SYN-ACK');

					const destinationIp = [...tcp.destination].join('.');
					upstream = net.connect({ host: destinationIp, port: tcp.destinationPort });
					upstream.on('error', () => { });
					upstream.on('connect', () => {
						upstreamReady = true;
						say('上游已连接', destinationIp + ':' + tcp.destinationPort);
						flushPending();
					});
					upstream.on('data', chunk => {
						for (let offset = 0; offset < chunk.length; offset += 1300) {
							const slice = chunk.subarray(offset, Math.min(offset + 1300, chunk.length));
							sendIp(0x18, slice, peerSeq);
							ourSeq = (ourSeq + slice.length) >>> 0;
						}
					});
					upstream.on('end', () => {
						sendIp(0x11, Buffer.alloc(0), (peerSeq + 1) >>> 0);
						ourSeq = (ourSeq + 1) >>> 0;
					});
					continue;
				}

				if (tcp.payload.length) {
					peerSeq = (tcp.seq + tcp.payload.length) >>> 0;
					if (upstreamReady) upstream.write(tcp.payload);
					else pendingWrites.push(tcp.payload);
				}

				if (tcp.flags & 0x01 && upstream) upstream.end(); // FIN
			}
		})().catch(error => {
			say('会话结束:', error.message);
			try { socket.destroy(); } catch { /* 忽略 */ }
		});

		socket.on('close', () => { });
	});

	return new Promise(resolve => {
		server.listen(0, '127.0.0.1', () => {
			resolve({
				port: server.address().port,
				close: () => new Promise(done => server.close(done))
			});
		});
	});
}

export { concatBytes };
