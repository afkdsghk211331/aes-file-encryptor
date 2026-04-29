/**
 * aes-file-encryptor — AES file encryption/decryption library.
 *
 * All three modes (CBC, CTR, CFB) use a minimal AES-128 JS implementation.
 * Web Crypto is used only for PBKDF2 key derivation, HKDF expansion,
 * HMAC-SHA256 integrity, and crypto.getRandomValues for salt/IV generation.
 *
 * File format (all modes):
 * ┌──────┬──────────┬──────────┬─────────────┬──────────┬──────────┐
 * │ Mode │ Salt(16) │ IV(16)   │ OrigSize(8) │ HMAC(32) │ EncData  │
 * │ (1B) │          │          │ LE uint64   │          │ (varies) │
 * └──────┴──────────┴──────────┴─────────────┴──────────┴──────────┘
 *
 * Mode byte: 0x01 = CBC, 0x02 = CTR, 0x03 = CFB
 *
 * CBC/CFB data: ChunkCount(4,BE) + [IV(16) + Ciphertext] * N
 *   CBC — per-chunk HKDF-derived key, independent chunks
 *   CFB — IV chains between chunks (standard CFB-128)
 *
 * CTR data: raw ciphertext (counter handles alignment).
 *
 * HMAC-SHA256 over header+ciphertext provides integrity verification.
 */

// =========================================================================
// Constants
// =========================================================================

const CHUNK_SIZE = 1024 * 1024; // 1 MiB
const AES_BLOCK = 16;

function toBuf(buf: Uint8Array): BufferSource {
  return (buf.buffer as ArrayBuffer).slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

const MODE_CBC = 0x01;
const MODE_CTR = 0x02;
const MODE_CFB = 0x03;

const SALT_SIZE = 16;
const IV_SIZE = 16;
const HMAC_SIZE = 32;
const PBKDF2_ITERATIONS = 100_000;

// =========================================================================
// Key derivation (Web Crypto — PBKDF2 / HKDF / HMAC)
// =========================================================================

async function deriveMasterKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const km = await crypto.subtle.importKey(
    "raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveBits"],
  );
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: toBuf(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    km, 128,
  ));
}

async function deriveChunkKey(
  masterKey: Uint8Array,
  chunkIndex: number,
): Promise<Uint8Array> {
  const info = new Uint8Array([(chunkIndex >>> 8) & 0xff, chunkIndex & 0xff]);
  const km = await crypto.subtle.importKey("raw", toBuf(masterKey), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", salt: new Uint8Array(0), info: toBuf(info), hash: "SHA-256" },
    km, 128,
  ));
}

async function deriveHmacKey(masterKey: Uint8Array): Promise<CryptoKey> {
  const info = new TextEncoder().encode("hmac");
  const km = await crypto.subtle.importKey("raw", toBuf(masterKey), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: new Uint8Array(0), info: toBuf(info), hash: "SHA-256" },
    km, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
  );
}

async function computeHmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, toBuf(data)));
}

async function verifyHmac(
  key: CryptoKey,
  data: Uint8Array,
  expected: Uint8Array,
): Promise<void> {
  const sig = await crypto.subtle.sign("HMAC", key, toBuf(data));
  const actual = new Uint8Array(sig);
  if (actual.length !== expected.length) throw new Error("Integrity check failed");
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  if (diff !== 0) throw new Error("Integrity check failed: wrong key or tampered data");
}

// =========================================================================
// PKCS#7 padding
// =========================================================================

function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padLen = 16 - (data.length % 16);
  const result = new Uint8Array(data.length + padLen);
  result.set(data);
  result.fill(padLen, data.length);
  return result;
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0) throw new Error("Cannot unpad empty data");
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > 16) throw new Error("Invalid PKCS7 padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid PKCS7 padding");
  }
  return data.slice(0, data.length - padLen);
}

// =========================================================================
// AES-128 Core (pure JS)
// =========================================================================

const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0xa2,0x89,0x62,0x66,0x1e,0x6e,0x1f,0x3a,0xc8,0xc1,0x47,
  0xa1,0x4b,0xa0,0xfd,0xa4,0xf0,0x7c,0x05,0x16,0xfb,0x9c,0xea,0xd5,0xb3,0x5d,0x99,
  0xd7,0x08,0x57,0x7e,0xf0,0x0f,0x1a,0xb2,0x9b,0x45,0xcf,0xf8,0x53,0x7a,0x9f,0x93,
  0x72,0x3a,0x96,0x3d,0xa2,0x2c,0x46,0x71,0x48,0x1b,0xa1,0x2d,0xfa,0xbe,0xe3,0x67,
  0x0a,0x8c,0x9e,0xe8,0x3b,0x1e,0xe0,0x37,0x04,0xce,0xc6,0x6b,0xa4,0x1e,0xa3,0x65,
  0x25,0x42,0xc9,0xc9,0xf3,0x61,0x23,0x73,0x96,0x3e,0x8e,0x64,0x43,0xb5,0x20,0x72,
  0xe0,0x8f,0x9f,0x83,0x8c,0x5b,0x41,0xc0,0xc1,0xb0,0xf4,0xf1,0x39,0x79,0xe0,0xd5,
]);

const INV_SBOX = new Uint8Array([
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]);

const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function gmul2(a: number): number { return (a << 1) ^ (a & 0x80 ? 0x1b : 0); }
function gmul3(a: number): number { return gmul2(a) ^ a; }
function gmul9(a: number): number { return gmul2(gmul2(gmul2(a))) ^ a; }
function gmul11(a: number): number { return gmul2(gmul2(gmul2(a)) ^ a) ^ a; }
function gmul13(a: number): number { return gmul2(gmul2(gmul2(a))) ^ gmul2(gmul2(a)) ^ a; }
function gmul14(a: number): number { return gmul2(gmul2(gmul2(a))) ^ gmul2(gmul2(a)) ^ gmul2(a); }

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const r = new Uint8Array(16);
  for (let i = 0; i < 16; i++) r[i] = a[i] ^ b[i];
  return r;
}

function aesKeyExpand(key: Uint8Array): Uint8Array[] {
  const nk = 4, nr = 10;
  const w: Uint8Array[] = [];
  for (let i = 0; i < nk; i++) w.push(key.slice(i * 4, (i + 1) * 4));
  for (let i = nk; i < nk * (nr + 1); i++) {
    const t = new Uint8Array(w[i - 1]);
    if (i % nk === 0) {
      const tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
      for (let j = 0; j < 4; j++) t[j] = SBOX[t[j]];
      t[0] ^= RCON[i / nk - 1];
    }
    const out = new Uint8Array(4);
    for (let j = 0; j < 4; j++) out[j] = w[i - nk][j] ^ t[j];
    w.push(out);
  }
  const rk: Uint8Array[] = [];
  for (let r = 0; r <= nr; r++) {
    const row = new Uint8Array(16);
    for (let i = 0; i < 4; i++) row.set(w[r * nk + i], i * 4);
    rk.push(row);
  }
  return rk;
}

/** AES-128 encrypt one 16-byte block */
function aesEncryptBlock(rk: Uint8Array[], block: Uint8Array): Uint8Array {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = block[i] ^ rk[0][i];
  for (let r = 1; r < 10; r++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    const t = new Uint8Array(s);
    s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
    s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
    for (let c = 0; c < 4; c++) {
      const i = c * 4;
      const a = s[i], b = s[i + 1], cc = s[i + 2], d = s[i + 3];
      s[i] = gmul2(a) ^ gmul3(b) ^ cc ^ d;
      s[i + 1] = a ^ gmul2(b) ^ gmul3(cc) ^ d;
      s[i + 2] = a ^ b ^ gmul2(cc) ^ gmul3(d);
      s[i + 3] = gmul3(a) ^ b ^ cc ^ gmul2(d);
    }
    for (let i = 0; i < 16; i++) s[i] ^= rk[r][i];
  }
  for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
  const t = new Uint8Array(s);
  s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
  s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
  s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
  for (let i = 0; i < 16; i++) s[i] ^= rk[10][i];
  return s;
}

/** AES-128 decrypt one 16-byte block */
function aesDecryptBlock(rk: Uint8Array[], block: Uint8Array): Uint8Array {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = block[i] ^ rk[10][i];
  for (let r = 9; r > 0; r--) {
    const t = new Uint8Array(s);
    s[1] = t[13]; s[5] = t[1]; s[9] = t[5]; s[13] = t[9];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
    s[3] = t[7]; s[11] = t[15]; s[15] = t[3];
    for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
    for (let i = 0; i < 16; i++) s[i] ^= rk[r][i];
    for (let c = 0; c < 4; c++) {
      const i = c * 4;
      const a = s[i], b = s[i + 1], cc = s[i + 2], d = s[i + 3];
      s[i] = gmul14(a) ^ gmul11(b) ^ gmul13(cc) ^ gmul9(d);
      s[i + 1] = gmul9(a) ^ gmul14(b) ^ gmul11(cc) ^ gmul13(d);
      s[i + 2] = gmul13(a) ^ gmul9(b) ^ gmul14(cc) ^ gmul11(d);
      s[i + 3] = gmul11(a) ^ gmul13(b) ^ gmul9(cc) ^ gmul14(d);
    }
  }
  const t = new Uint8Array(s);
  s[1] = t[13]; s[5] = t[1]; s[9] = t[5]; s[13] = t[9];
  s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
  s[3] = t[7]; s[11] = t[15]; s[15] = t[3];
  for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
  for (let i = 0; i < 16; i++) s[i] ^= rk[0][i];
  return s;
}

// =========================================================================
// CBC Mode (manual AES-128)
// =========================================================================

async function encryptCBC(
  masterKey: Uint8Array,
  plaintext: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);
    const chunkKey = await deriveChunkKey(masterKey, i);

    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const padded = pkcs7Pad(chunk);
    const rk = aesKeyExpand(chunkKey);
    const ct = new Uint8Array(padded.length);
    let prev: Uint8Array = iv;

    for (let off = 0; off < padded.length; off += AES_BLOCK) {
      const ptBlock = padded.slice(off, off + AES_BLOCK);
      const encBlock = aesEncryptBlock(rk, xor16(prev, ptBlock));
      ct.set(encBlock, off);
      prev = encBlock;
    }

    const buf = new Uint8Array(IV_SIZE + ct.length);
    buf.set(iv, 0);
    buf.set(ct, IV_SIZE);
    parts.push(buf);
    onProgress?.((i + 1) / chunkCount);
  }

  const cc = new Uint8Array(4);
  new DataView(cc.buffer).setUint32(0, chunkCount, false);
  return concat([cc, ...parts]);
}

async function decryptCBC(
  masterKey: Uint8Array,
  ciphertext: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = new DataView(ciphertext.buffer).getUint32(0, false);
  const parts: Uint8Array[] = [];
  let offset = 4;

  for (let i = 0; i < chunkCount; i++) {
    const iv = ciphertext.slice(offset, offset + IV_SIZE);
    offset += IV_SIZE;
    const chunkKey = await deriveChunkKey(masterKey, i);

    const chunkDataLen = i < chunkCount - 1
      ? CHUNK_SIZE + AES_BLOCK
      : ciphertext.length - offset;
    const ctChunk = ciphertext.slice(offset, offset + chunkDataLen);
    offset += chunkDataLen;

    const rk = aesKeyExpand(chunkKey);
    const blocks = ctChunk.length / AES_BLOCK;
    const padded = new Uint8Array(ctChunk.length);
    let prev = iv;

    for (let b = 0; b < blocks; b++) {
      const ctBlock = ctChunk.slice(b * AES_BLOCK, (b + 1) * AES_BLOCK);
      const ptBlock = xor16(prev, aesDecryptBlock(rk, ctBlock));
      padded.set(ptBlock, b * AES_BLOCK);
      prev = ctBlock;
    }

    parts.push(pkcs7Unpad(padded));
    onProgress?.((i + 1) / chunkCount);
  }

  return concat(parts);
}

// =========================================================================
// CTR Mode (manual AES-128)
// =========================================================================

async function processCTR(
  masterKey: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];
  let blockNo = 0;
  const rk = aesKeyExpand(masterKey);

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunk = data.slice(start, end);

    const counter = new Uint8Array(IV_SIZE);
    counter.set(iv);
    const cv = new DataView(counter.buffer, counter.byteOffset + 8, 8);
    cv.setBigUint64(0, BigInt(blockNo));

    const out = new Uint8Array(chunk.length);
    for (let off = 0; off < chunk.length; off += AES_BLOCK) {
      const len = Math.min(AES_BLOCK, chunk.length - off);
      const ks = aesEncryptBlock(rk, counter);
      for (let j = 0; j < len; j++) out[off + j] = chunk[off + j] ^ ks[j];
      cv.setBigUint64(0, cv.getBigUint64(0) + 1n);
    }

    parts.push(out);
    blockNo += Math.ceil(chunk.length / AES_BLOCK);
    onProgress?.((i + 1) / chunkCount);
  }

  return concat(parts);
}

// =========================================================================
// CFB Mode (manual AES-128)
// =========================================================================

async function processCFB(
  masterKey: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array,
  decrypt: boolean,
): Promise<Uint8Array> {
  const rk = aesKeyExpand(masterKey);
  const result = new Uint8Array(data.length);
  let feedback = new Uint8Array(iv);

  for (let off = 0; off < data.length; off += AES_BLOCK) {
    const len = Math.min(AES_BLOCK, data.length - off);
    const ks = aesEncryptBlock(rk, feedback);
    for (let j = 0; j < len; j++) result[off + j] = data[off + j] ^ ks[j];

    if (len < AES_BLOCK) {
      const next = new Uint8Array(AES_BLOCK);
      next.set(decrypt ? data.slice(off, off + len) : result.slice(off, off + len));
      next.set(feedback.slice(len), len);
      feedback = next;
    } else {
      feedback = decrypt
        ? data.slice(off, off + AES_BLOCK)
        : result.slice(off, off + AES_BLOCK);
    }
  }
  return result;
}

async function encryptCFB(
  masterKey: Uint8Array,
  plaintext: Uint8Array,
  iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);
    const chunkKey = await deriveChunkKey(masterKey, i);

    const chunkIv = i === 0 ? iv : parts[parts.length - 1].slice(-AES_BLOCK);
    const ct = await processCFB(chunkKey, chunk, chunkIv, false);

    if (i === 0) {
      const buf = new Uint8Array(IV_SIZE + ct.length);
      buf.set(iv, 0);
      buf.set(ct, IV_SIZE);
      parts.push(buf);
    } else {
      parts.push(ct);
    }
    onProgress?.((i + 1) / chunkCount);
  }

  const cc = new Uint8Array(4);
  new DataView(cc.buffer).setUint32(0, chunkCount, false);
  return concat([cc, ...parts]);
}

async function decryptCFB(
  masterKey: Uint8Array,
  ciphertext: Uint8Array,
  _iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = new DataView(ciphertext.buffer).getUint32(0, false);
  const parts: Uint8Array[] = [];
  let offset = 4;
  let prevCtChunk: Uint8Array | null = null;

  for (let i = 0; i < chunkCount; i++) {
    let chunkIv: Uint8Array;
    if (i === 0) {
      chunkIv = ciphertext.slice(offset, offset + IV_SIZE);
      offset += IV_SIZE;
    } else {
      chunkIv = prevCtChunk!.slice(-AES_BLOCK);
    }

    const chunkDataLen = i < chunkCount - 1 ? CHUNK_SIZE : ciphertext.length - offset;
    const ctChunk = ciphertext.slice(offset, offset + chunkDataLen);
    offset += chunkDataLen;

    const chunkKey = await deriveChunkKey(masterKey, i);
    const ptChunk = await processCFB(chunkKey, ctChunk, chunkIv, true);
    parts.push(ptChunk);
    prevCtChunk = ctChunk;
    onProgress?.((i + 1) / chunkCount);
  }

  return concat(parts);
}

// =========================================================================
// Helpers
// =========================================================================

function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// =========================================================================
// Public API
// =========================================================================

export type EncryptionMode = "CBC" | "CTR" | "CFB";

export interface CryptoOptions {
  onProgress?: (pct: number) => void;
}

export async function encryptFile(
  file: File,
  key: string,
  mode: EncryptionMode,
  options?: CryptoOptions,
): Promise<Blob> {
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const masterKey = await deriveMasterKey(key, salt);

  let encryptedData: Uint8Array;
  if (mode === "CBC") {
    encryptedData = await encryptCBC(masterKey, plaintext, options?.onProgress);
  } else if (mode === "CTR") {
    encryptedData = await processCTR(masterKey, plaintext, iv, options?.onProgress);
  } else {
    encryptedData = await encryptCFB(masterKey, plaintext, iv, options?.onProgress);
  }

  const modeByte = new Uint8Array([
    mode === "CBC" ? MODE_CBC : mode === "CTR" ? MODE_CTR : MODE_CFB,
  ]);
  const origSize = new Uint8Array(8);
  new DataView(origSize.buffer).setBigUint64(0, BigInt(plaintext.length), true);

  const header = concat([modeByte, salt, iv, origSize]);
  const hmacKey = await deriveHmacKey(masterKey);
  const hmac = await computeHmac(hmacKey, concat([header, encryptedData]));

  return new Blob([concat([header, hmac, encryptedData]) as unknown as BlobPart]);
}

export async function decryptFile(
  file: File,
  key: string,
  mode: EncryptionMode,
  options?: CryptoOptions,
): Promise<Blob> {
  const data = new Uint8Array(await file.arrayBuffer());
  const expectedMode = mode === "CBC" ? MODE_CBC : mode === "CTR" ? MODE_CTR : MODE_CFB;

  if (data[0] !== expectedMode) {
    throw new Error(
      `Mode mismatch: expected ${mode} but file header says ${
        data[0] === MODE_CBC ? "CBC" : data[0] === MODE_CTR ? "CTR" : "CFB"
      }`,
    );
  }

  const salt = data.slice(1, 1 + SALT_SIZE);
  const iv = data.slice(1 + SALT_SIZE, 1 + SALT_SIZE + IV_SIZE);
  const origSize = Number(
    new DataView(data.buffer).getBigUint64(1 + SALT_SIZE + IV_SIZE, true),
  );
  const hmacStart = 1 + SALT_SIZE + IV_SIZE + 8;
  const hmac = data.slice(hmacStart, hmacStart + HMAC_SIZE);
  const encryptedData = data.slice(hmacStart + HMAC_SIZE);

  const masterKey = await deriveMasterKey(key, salt);
  const hmacKey = await deriveHmacKey(masterKey);
  const header = data.slice(0, hmacStart);
  await verifyHmac(hmacKey, concat([header, encryptedData]), hmac);

  let decrypted: Uint8Array;
  if (mode === "CBC") {
    decrypted = await decryptCBC(masterKey, encryptedData, options?.onProgress);
  } else if (mode === "CTR") {
    decrypted = await processCTR(masterKey, encryptedData, iv, options?.onProgress);
  } else {
    decrypted = await decryptCFB(masterKey, encryptedData, iv, options?.onProgress);
  }

  return new Blob([decrypted.slice(0, origSize) as unknown as BlobPart]);
}
