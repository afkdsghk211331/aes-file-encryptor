/**
 * aes-file-encryptor — AES file encryption/decryption library.
 *
 * Supports AES-CBC, AES-CTR, and AES-CFB-128 modes via the Web Crypto API.
 * CFB mode uses a minimal AES-128 JS implementation for single-block
 * encryption (Web Crypto lacks AES-ECB).
 * Designed for browser use with chunked processing to handle large files.
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

/** Cast Uint8Array to BufferSource for Web Crypto API (TS 5.4 compat) */
function bs(buf: Uint8Array): BufferSource {
  return buf.buffer as ArrayBuffer;
}

const MODE_CBC = 0x01;
const MODE_CTR = 0x02;
const MODE_CFB = 0x03;

const SALT_SIZE = 16;
const IV_SIZE = 16;
const HMAC_SIZE = 32;
const PBKDF2_ITERATIONS = 100_000;

// =========================================================================
// Key derivation
// =========================================================================

async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: bs(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-CTR", length: 256 },
    true, // extractable — needed for HKDF sub-key derivation
    ["encrypt", "decrypt"],
  );
}

/** Per-chunk AES-CBC sub-key for CBC mode (HKDF from master key) */
async function deriveChunkKey(
  masterKey: CryptoKey,
  chunkIndex: number,
): Promise<CryptoKey> {
  const rawKey = await crypto.subtle.exportKey("raw", masterKey);
  const info = new Uint8Array([(chunkIndex >>> 8) & 0xff, chunkIndex & 0xff]);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: bs(new Uint8Array(0)), info, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// =========================================================================
// HMAC integrity
// =========================================================================

async function deriveHmacKey(masterKey: CryptoKey): Promise<CryptoKey> {
  const rawKey = await crypto.subtle.exportKey("raw", masterKey);
  const info = new TextEncoder().encode("hmac");
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: bs(new Uint8Array(0)), info, hash: "SHA-256" },
    keyMaterial,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function computeHmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign("HMAC", key, bs(data));
  return new Uint8Array(sig);
}

async function verifyHmac(
  key: CryptoKey,
  data: Uint8Array,
  expected: Uint8Array,
): Promise<void> {
  const sig = await crypto.subtle.sign("HMAC", key, bs(data));
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
// AES-128 in JS (for CFB mode block cipher — Web Crypto has no ECB)
// =========================================================================

// S-box
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

/** AES-128 key expansion */
function aes128KeyExpand(key: Uint8Array): Uint8Array[] {
  const nk = 4; // 128-bit key
  const nr = 10; // rounds
  const words: Uint8Array[] = [];
  for (let i = 0; i < nk; i++) {
    words.push(key.slice(i * 4, (i + 1) * 4));
  }
  for (let i = nk; i < nk * (nr + 1); i++) {
    const prev = words[i - 1];
    const word = new Uint8Array(4);
    if (i % nk === 0) {
      // RotWord + SubWord + Rcon
      const tmp = new Uint8Array([prev[1], prev[2], prev[3], prev[0]]);
      for (let j = 0; j < 4; j++) word[j] = SBOX[tmp[j]];
      const rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
      word[0] ^= rcon[i / nk - 1];
    } else {
      word.set(prev);
    }
    const w = new Uint8Array(4);
    for (let j = 0; j < 4; j++) w[j] = words[i - nk][j] ^ word[j];
    words.push(w);
  }
  // Group into round keys (each 16 bytes)
  const roundKeys: Uint8Array[] = [];
  for (let r = 0; r <= nr; r++) {
    const rk = new Uint8Array(16);
    for (let i = 0; i < 4; i++) rk.set(words[r * nk + i], i * 4);
    roundKeys.push(rk);
  }
  return roundKeys;
}

/** AES-128 single-block encrypt (16 bytes input → 16 bytes output) */
function aes128EncryptBlock(roundKeys: Uint8Array[], block: Uint8Array): Uint8Array {
  const nr = 10;
  // State: column-major 4x4
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) s[i] = block[i] ^ roundKeys[0][i];

  for (let r = 1; r < nr; r++) {
    // SubBytes
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    // ShiftRows
    const tmp = new Uint8Array(16);
    tmp.set(s);
    s[1] = tmp[5];  s[5] = tmp[9];  s[9]  = tmp[13]; s[13] = tmp[1];
    s[2] = tmp[10]; s[6] = tmp[14]; s[10] = tmp[2];   s[14] = tmp[6];
    s[3] = tmp[15]; s[7] = tmp[3];  s[11] = tmp[7];   s[15] = tmp[11];
    // MixColumns
    for (let c = 0; c < 4; c++) {
      const i = c * 4;
      const s0 = s[i], s1 = s[i+1], s2 = s[i+2], s3 = s[i+3];
      s[i]   = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
      s[i+1] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
      s[i+2] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
      s[i+3] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
    }
    // AddRoundKey
    for (let i = 0; i < 16; i++) s[i] ^= roundKeys[r][i];
  }
  // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
  for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
  const tmp = new Uint8Array(16);
  tmp.set(s);
  s[1] = tmp[5];  s[5] = tmp[9];  s[9]  = tmp[13]; s[13] = tmp[1];
  s[2] = tmp[10]; s[6] = tmp[14]; s[10] = tmp[2];   s[14] = tmp[6];
  s[3] = tmp[15]; s[7] = tmp[3];  s[11] = tmp[7];   s[15] = tmp[11];
  for (let i = 0; i < 16; i++) s[i] ^= roundKeys[nr][i];
  return s;
}

/** GF(2^8) multiplication helpers */
function gmul2(a: number): number {
  return (a << 1) ^ (a & 0x80 ? 0x1b : 0);
}
function gmul3(a: number): number {
  return gmul2(a) ^ a;
}

/**
 * AES-128-CFB-128 encryption/decryption.
 * Processes the entire plaintext in 16-byte blocks sequentially.
 * For large files, this runs in a single async pass — memory-efficient
 * since it outputs ciphertext incrementally.
 */
async function processCFB(
  masterKey: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const rawKey = await crypto.subtle.exportKey("raw", masterKey);
  const roundKeys = aes128KeyExpand(new Uint8Array(rawKey));
  const result = new Uint8Array(plaintext.length);
  let feedback = new Uint8Array(iv); // IV for first block

  for (let offset = 0; offset < plaintext.length; offset += 16) {
    const len = Math.min(16, plaintext.length - offset);
    // Encrypt feedback block → keystream
    const keystream = aes128EncryptBlock(roundKeys, feedback);
    // XOR with plaintext (may be < 16 bytes for last block)
    for (let i = 0; i < len; i++) {
      result[offset + i] = plaintext[offset + i] ^ keystream[i];
    }
    // Feedback for next block is the ciphertext (truncated for last partial block)
    if (len < 16) {
      const next = new Uint8Array(16);
      next.set(result.slice(offset, offset + len));
      // Pad remainder with original feedback bytes (CFB rule)
      next.set(feedback.slice(len), len);
      feedback = next;
    } else {
      feedback = result.slice(offset, offset + 16);
    }
  }
  return result;
}

// =========================================================================
// CBC mode
// =========================================================================

async function encryptCBC(
  masterKey: CryptoKey,
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

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv: bs(iv) },
      chunkKey,
      bs(padded),
    );

    const buf = new Uint8Array(IV_SIZE + encrypted.byteLength);
    buf.set(iv, 0);
    buf.set(new Uint8Array(encrypted), IV_SIZE);
    parts.push(buf);
    onProgress?.((i + 1) / chunkCount);
  }

  const chunkCountBuf = new Uint8Array(4);
  new DataView(chunkCountBuf.buffer).setUint32(0, chunkCount, false);
  return concatUint8Arrays([chunkCountBuf, ...parts]);
}

async function decryptCBC(
  masterKey: CryptoKey,
  ciphertext: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = new DataView(ciphertext.buffer).getUint32(0, false);
  const parts: Uint8Array[] = [];
  let offset = 4;
  const fullChunkCtLen = CHUNK_SIZE + 16;

  for (let i = 0; i < chunkCount; i++) {
    const iv = ciphertext.slice(offset, offset + IV_SIZE);
    offset += IV_SIZE;

    const chunkDataLen = i < chunkCount - 1 ? fullChunkCtLen : ciphertext.length - offset;
    const chunkCiphertext = ciphertext.slice(offset, offset + chunkDataLen);
    offset += chunkDataLen;

    const chunkKey = await deriveChunkKey(masterKey, i);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: bs(iv) },
      chunkKey,
      bs(chunkCiphertext),
    );

    parts.push(pkcs7Unpad(new Uint8Array(decrypted)));
    onProgress?.((i + 1) / chunkCount);
  }

  return concatUint8Arrays(parts);
}

// =========================================================================
// CTR mode
// =========================================================================

async function encryptCTR(
  key: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];
  let blockCount = 0;

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);

    const counter = new Uint8Array(IV_SIZE);
    counter.set(iv);
    addBigUint64(counter, BigInt(blockCount));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-CTR", counter, length: 128 },
      key,
      bs(chunk),
    );

    parts.push(new Uint8Array(encrypted));
    blockCount += Math.ceil(chunk.length / 16);
    onProgress?.((i + 1) / chunkCount);
  }

  return concatUint8Arrays(parts);
}

async function decryptCTR(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  return encryptCTR(key, ciphertext, iv, onProgress);
}

function addBigUint64(buf: Uint8Array, value: bigint): void {
  const view = new DataView(buf.buffer, buf.byteOffset + 8, 8);
  const current = view.getBigUint64(0);
  view.setBigUint64(0, current + value);
}

// =========================================================================
// CFB mode
// =========================================================================

async function encryptCFB(
  masterKey: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];
  let offset = 0;

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);

    const chunkIv = i === 0 ? iv : parts[parts.length - 1].slice(-16);
    const ctChunk = await processCFB(masterKey, chunk, chunkIv);

    if (i === 0) {
      const buf = new Uint8Array(IV_SIZE + ctChunk.length);
      buf.set(iv, 0);
      buf.set(ctChunk, IV_SIZE);
      parts.push(buf);
    } else {
      parts.push(ctChunk);
    }
    offset += chunk.length;
    onProgress?.((i + 1) / chunkCount);
  }

  const chunkCountBuf = new Uint8Array(4);
  new DataView(chunkCountBuf.buffer).setUint32(0, chunkCount, false);
  return concatUint8Arrays([chunkCountBuf, ...parts]);
}

async function decryptCFB(
  masterKey: CryptoKey,
  ciphertext: Uint8Array,
  _iv: Uint8Array,
  onProgress?: (pct: number) => void,
): Promise<Uint8Array> {
  const chunkCount = new DataView(ciphertext.buffer).getUint32(0, false);
  const parts: Uint8Array[] = [];
  let offset = 4;

  for (let i = 0; i < chunkCount; i++) {
    let chunkIv: Uint8Array;
    let ctChunk: Uint8Array;

    if (i === 0) {
      chunkIv = ciphertext.slice(offset, offset + IV_SIZE);
      offset += IV_SIZE;
    } else {
      chunkIv = parts[parts.length - 1]; // last 16 bytes of previous plaintext = ciphertext
    }

    const chunkDataLen = i < chunkCount - 1 ? CHUNK_SIZE : ciphertext.length - offset;
    ctChunk = ciphertext.slice(offset, offset + chunkDataLen);
    offset += chunkDataLen;

    const ptChunk = await processCFB(masterKey, ctChunk, chunkIv);
    parts.push(ptChunk);
    onProgress?.((i + 1) / chunkCount);
  }

  return concatUint8Arrays(parts);
}

// =========================================================================
// Helpers
// =========================================================================

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
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
  /** Called with progress 0–1 during encryption/decryption */
  onProgress?: (pct: number) => void;
}

/** Encrypt a file with optional progress callback */
export async function encryptFile(
  file: File,
  key: string,
  mode: EncryptionMode,
  options?: CryptoOptions,
): Promise<Blob> {
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const masterKey = await deriveKey(key, salt);

  let encryptedData: Uint8Array;
  if (mode === "CBC") {
    encryptedData = await encryptCBC(masterKey, plaintext, options?.onProgress);
  } else if (mode === "CTR") {
    encryptedData = await encryptCTR(masterKey, plaintext, iv, options?.onProgress);
  } else {
    encryptedData = await encryptCFB(masterKey, plaintext, iv, options?.onProgress);
  }

  const modeByte = new Uint8Array([
    mode === "CBC" ? MODE_CBC : mode === "CTR" ? MODE_CTR : MODE_CFB,
  ]);
  const origSize = new Uint8Array(8);
  new DataView(origSize.buffer).setBigUint64(0, BigInt(plaintext.length), true);

  const header = concatUint8Arrays([modeByte, salt, iv, origSize]);
  const hmacKey = await deriveHmacKey(masterKey);
  const hmac = await computeHmac(hmacKey, concatUint8Arrays([header, encryptedData]));

  return new Blob([concatUint8Arrays([header, hmac, encryptedData]) as unknown as BlobPart]);
}

/** Decrypt a file with optional progress callback. Verifies HMAC integrity. */
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
  const hmac = data.slice(
    1 + SALT_SIZE + IV_SIZE + 8,
    1 + SALT_SIZE + IV_SIZE + 8 + HMAC_SIZE,
  );
  const encryptedData = data.slice(1 + SALT_SIZE + IV_SIZE + 8 + HMAC_SIZE);

  const masterKey = await deriveKey(key, salt);
  const hmacKey = await deriveHmacKey(masterKey);
  const header = data.slice(0, 1 + SALT_SIZE + IV_SIZE + 8);
  await verifyHmac(hmacKey, concatUint8Arrays([header, encryptedData]), hmac);

  let decrypted: Uint8Array;
  if (mode === "CBC") {
    decrypted = await decryptCBC(masterKey, encryptedData, options?.onProgress);
  } else if (mode === "CTR") {
    decrypted = await decryptCTR(masterKey, encryptedData, iv, options?.onProgress);
  } else {
    decrypted = await decryptCFB(masterKey, encryptedData, iv, options?.onProgress);
  }

  return new Blob([decrypted.slice(0, origSize) as unknown as BlobPart]);
}
