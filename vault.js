// Reads private-data.enc with the WebCrypto API; the format is described in exporter/envelope.js.
// Runs unchanged in the browser and in Node (the tests import it).
const MAGIC = 'SOPX';
const SALT_BYTES = 16;
const IV_BYTES = 12;
const HEADER_BYTES = 10 + SALT_BYTES + IV_BYTES;

export function parseHeader(buffer) {
  const bytes = new Uint8Array(buffer);
  const magic = String.fromCharCode(...bytes.subarray(0, 4));
  if (bytes.length < HEADER_BYTES + 16 || magic !== MAGIC || bytes[4] !== 1 || bytes[5] !== 1) {
    throw new Error('private-data.enc biçimi tanınmadı');
  }
  return {
    iterations: new DataView(bytes.buffer, bytes.byteOffset).getUint32(6),
    salt: bytes.subarray(10, 10 + SALT_BYTES),
    iv: bytes.subarray(10 + SALT_BYTES, HEADER_BYTES),
    header: bytes.subarray(0, HEADER_BYTES),
    body: bytes.subarray(HEADER_BYTES),
  };
}

/** PBKDF2-HMAC-SHA256 → the 32 raw key bytes. Callers wipe them (fill(0)) once imported. */
export async function deriveKeyBytes(password, { salt, iterations }) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material, 256));
}

/** An AES-256-GCM key that cannot be exported again, not even by this page. */
export const importKey = (bytes) => crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['decrypt']);

export async function deriveKey(password, header) {
  const bytes = await deriveKeyBytes(password, header);
  try {
    return await importKey(bytes);
  } finally {
    bytes.fill(0);
  }
}

/** Rejects (OperationError) when the key is wrong or the file was altered. */
export async function decrypt(key, { iv, header, body }) {
  const packed = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header }, key, body);
  const stream = new Blob([packed]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(stream).text());
}
