// 通用工具：超时、字节拼接、带缓冲的 socket 读取器。
// 之所以自己实现 ByteReader 而不是用 async iterator：握手完成后需要把
// 多读到的字节“还回去”（socket.unshift）再交给 tls.connect 复用同一个 socket，
// 而 Readable 的 async iterator 提前退出会 destroy 掉流。

export function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return Promise.race([
			promise,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(message)), timeoutMs);
			})
		]);
	} finally {
		clearTimeout(timer);
	}
}

export function toBuffer(data) {
	if (Buffer.isBuffer(data)) return data;
	if (typeof data === 'string') return Buffer.from(data, 'latin1');
	if (data instanceof Uint8Array) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
	if (data instanceof ArrayBuffer) return Buffer.from(data);
	return Buffer.alloc(0);
}

export function concatBytes(...chunks) {
	return Buffer.concat(chunks.filter(Boolean).map(toBuffer));
}

export function indexOfHeaderEnd(buffer) {
	return buffer.indexOf('\r\n\r\n');
}

export function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

export class ByteReader {
	constructor(socket, { timeoutMs = 10000 } = {}) {
		this.socket = socket;
		this.timeoutMs = timeoutMs;
		this.buffer = Buffer.alloc(0);
		this.ended = false;
		this.error = null;
		this.waiter = null;

		this._onData = chunk => {
			this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
			this._wake();
		};
		this._onEnd = () => {
			this.ended = true;
			this._wake();
		};
		this._onClose = () => {
			this.ended = true;
			this._wake();
		};
		this._onError = error => {
			this.error = error;
			this._wake();
		};

		socket.on('data', this._onData);
		socket.on('end', this._onEnd);
		socket.on('close', this._onClose);
		socket.on('error', this._onError);
	}

	_wake() {
		if (!this.waiter) return;
		const waiter = this.waiter;
		this.waiter = null;
		waiter();
	}

	async _pull() {
		if (this.error) throw this.error;
		if (this.ended) throw new Error('连接已被对端关闭');
		await new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.waiter = null;
				reject(new Error('读取超时'));
			}, this.timeoutMs);
			this.waiter = () => {
				clearTimeout(timer);
				resolve();
			};
		});
		if (this.error) throw this.error;
	}

	async readExactly(length) {
		while (this.buffer.length < length) await this._pull();
		const out = this.buffer.subarray(0, length);
		this.buffer = this.buffer.subarray(length);
		return out;
	}

	async readSome() {
		if (!this.buffer.length) await this._pull();
		if (!this.buffer.length) throw new Error('连接已被对端关闭');
		const out = this.buffer;
		this.buffer = Buffer.alloc(0);
		return out;
	}

	async readUntil(needle) {
		const target = toBuffer(needle);
		for (;;) {
			const index = this.buffer.indexOf(target);
			if (index !== -1) {
				const out = this.buffer.subarray(0, index);
				this.buffer = this.buffer.subarray(index + target.length);
				return out;
			}
			if (this.buffer.length > 64 * 1024) throw new Error('未找到预期的分隔符');
			await this._pull();
		}
	}

	/** 解绑监听并把多读的字节塞回 socket，供 tls.connect 继续读取 */
	detach() {
		const rest = this.buffer;
		this.buffer = Buffer.alloc(0);
		this.socket.off('data', this._onData);
		this.socket.off('end', this._onEnd);
		this.socket.off('close', this._onClose);
		this.socket.off('error', this._onError);
		this.socket.pause();
		if (rest.length) this.socket.unshift(rest);
		return rest.length;
	}
}
