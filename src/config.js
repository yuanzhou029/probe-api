// 超时与容量参数，默认值与 _worker.js:3-8 对齐，可用环境变量覆盖。
export const CHECK_TIMEOUT_MS = Number(process.env.CHECK_TIMEOUT_MS || 12000);
export const CONNECT_TIMEOUT_MS = Number(process.env.CONNECT_TIMEOUT_MS || 9999);
export const READ_TIMEOUT_MS = Number(process.env.READ_TIMEOUT_MS || 8000);
export const MAX_RESPONSE_BYTES = Number(process.env.MAX_RESPONSE_BYTES || 96 * 1024);
