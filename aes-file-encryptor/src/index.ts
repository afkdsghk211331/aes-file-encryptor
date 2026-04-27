/**
 * aes-file-encryptor — AES file encryption/decryption library.
 *
 * Supports AES-CBC and AES-CTR modes via the Web Crypto API.
 * Designed for browser use with chunked processing to handle large files.
 *
 * File format (all modes):
 * ┌──────┬──────────┬──────────┬──────┬─────────────┬──────────┐
 * │ Mode │ Salt(16) │ IV(16)   │ Data │ (optional)  │          │
 * │(1B)  │          │          │      │             │          │
 * └──────┴──────────┴──────────┴──────┴─────────────┴──────────┘
 *
 * Mode byte: 0x01 = CBC, 0x02 = CTR
 * Salt: used for PBKDF2 key derivation from passphrase
 * IV: initialisation vector / counter nonce
 * Data: for CBC — chunks of (IV(16) + ciphertext), each chunk uses a
 *       derived key so chunks are independent (enables parallel decrypt).
 *       For CTR — raw ciphertext (counter handles alignment naturally).
 *
 * The original file size (uint64 LE, 8 bytes) is appended to the end
 * of the file for both modes, so decryption knows the exact output size
 * (needed to strip PKCS7 padding in CBC).
 */

// =========================================================================
// Constants
// =========================================================================

/** 1 MiB — chunk size for CBC mode to avoid browser memory pressure */
const CHUNK_SIZE = 1024 * 1024;

const MODE_CBC = 0x01;
const MODE_CTR = 0x02;

const SALT_SIZE = 16;
const IV_SIZE = 16;

/** PBKDF2 iteration count — balances security vs. user wait time */
const PBKDF2_ITERATIONS = 100_000;

// =========================================================================
// Key derivation
// =========================================================================

/**
 * Derive a 256-bit AES key from a passphrase using PBKDF2-SHA256.
 * The same passphrase + salt always produces the same key.
 */
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
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 }, // base algorithm for derivation
    true, // extractable — needed for HKDF chunk-key derivation
    ["encrypt", "decrypt"],
  );
}

/**
 * For CBC chunked mode: derive a per-chunk sub-key from the master key
 * via HKDF-SHA256. This makes each chunk's encryption independent,
 * breaking the CBC chaining dependency between chunks.
 *
 * The "info" parameter is a 2-byte big-endian chunk index.
 */
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
    { name: "HKDF", salt: new Uint8Array(0), info, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// =========================================================================
// PKCS#7 padding (CBC only — CTR doesn't need padding)
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
  if (padLen < 1 || padLen > 16) throw new Error("Invalid padding");
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid padding");
  }
  return data.slice(0, data.length - padLen);
}

// =========================================================================
// CBC mode — chunked with per-chunk derived keys
// =========================================================================

/**
 * Encrypt with AES-CBC in chunked mode.
 *
 * Each chunk gets:
 *   1. A fresh random IV (16 bytes)
 *   2. A per-chunk sub-key derived from the master key
 *   3. PKCS#7 padding to align to 16-byte AES blocks
 *
 * Output per chunk: IV(16) + ciphertext
 * This structure means chunks are independent — decryption doesn't
 * need data from previous chunks (unlike standard CBC chaining).
 */
async function encryptCBC(
  masterKey: CryptoKey,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);

    // Unique sub-key per chunk + random IV = independent chunk encryption
    const chunkKey = await deriveChunkKey(masterKey, i);
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const padded = pkcs7Pad(chunk);

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      chunkKey,
      padded,
    );

    // Store IV then ciphertext for this chunk
    const buf = new Uint8Array(IV_SIZE + encrypted.byteLength);
    buf.set(iv, 0);
    buf.set(new Uint8Array(encrypted), IV_SIZE);
    parts.push(buf);
  }

  // Also store chunk count for decryption (4 bytes, big-endian)
  const chunkCountBuf = new Uint8Array(4);
  new DataView(chunkCountBuf.buffer).setUint32(0, chunkCount, false);
  return concatUint8Arrays([chunkCountBuf, ...parts]);
}

/**
 * Decrypt AES-CBC chunked ciphertext.
 *
 * Format: chunkCount(4) + [IV(16) + ciphertext] * chunkCount
 *
 * For each chunk:
 *   1. Extract the 16-byte IV
 *   2. Re-derive the per-chunk sub-key from master key + index
 *   3. Decrypt and remove PKCS#7 padding
 *
 * Because each chunk has its own key, they could theoretically be
 * decrypted in parallel (though we do it sequentially here for
 * simplicity and compatibility).
 */
async function decryptCBC(
  masterKey: CryptoKey,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const chunkCount = new DataView(ciphertext.buffer).getUint32(0, false);
  const parts: Uint8Array[] = [];
  let offset = 4; // skip chunk count header

  for (let i = 0; i < chunkCount; i++) {
    // Extract IV
    const iv = ciphertext.slice(offset, offset + IV_SIZE);
    offset += IV_SIZE;

    // Determine chunk ciphertext size
    // For the last chunk, take everything remaining.
    // For other chunks, we need to know the size.
    // Since each chunk's ciphertext is always a multiple of 16 (AES block),
    // and we know the chunkCount, we can calculate.
    // Actually, we can't easily know boundaries without storing sizes.
    //
    // Better approach: since we know the original chunk size (CHUNK_SIZE
    // padded to multiple of 16 = CHUNK_SIZE for CHUNK_SIZE=1MiB),
    // all chunks except the last have the same ciphertext size.
    // CHUNK_SIZE (1 MiB) is already a multiple of 16, so padded size
    // = CHUNK_SIZE + 16.
    //
    // Let's compute: plaintext chunk ≤ CHUNK_SIZE. After PKCS7 padding,
    // the size is ceil(plainLen/16)*16. For a full 1 MiB chunk, that's
    // 1 MiB + 16. For the last chunk it varies.
    //
    // Simpler solution: store each chunk's ciphertext length (2 bytes).
    // Let me reconsider the format.

    // For now, let's use a different approach: since we know all
    // intermediate chunks have the same size when plaintext chunk size
    // is fixed, and we know the last chunk is the remainder.
    //
    // Full chunk: plaintext = CHUNK_SIZE → after PKCS7 pad = CHUNK_SIZE + 16
    // → ciphertext = CHUNK_SIZE + 16 → total chunk = IV(16) + CHUNK_SIZE + 16
    const fullChunkSize = IV_SIZE + CHUNK_SIZE + 16;

    let chunkDataLen: number;
    if (i < chunkCount - 1) {
      chunkDataLen = fullChunkSize - IV_SIZE; // ciphertext length
    } else {
      chunkDataLen = ciphertext.length - offset; // remainder
    }

    const chunkCiphertext = ciphertext.slice(offset, offset + chunkDataLen);
    offset += chunkDataLen;

    // Re-derive the per-chunk key and decrypt
    const chunkKey = await deriveChunkKey(masterKey, i);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      chunkKey,
      chunkCiphertext,
    );

    // Remove PKCS7 padding
    parts.push(pkcs7Unpad(new Uint8Array(decrypted)));
  }

  return concatUint8Arrays(parts);
}

// =========================================================================
// CTR mode — simple, no padding needed
// =========================================================================

/**
 * Encrypt with AES-CTR.
 *
 * CTR mode XORs a keystream (encrypted counter blocks) with plaintext.
 * No padding is needed — any file size works naturally.
 *
 * The counter is a 128-bit value that increments for each 16-byte block.
 * We use a random IV as the starting counter value.
 *
 * For large files we process in chunks; the counter value is advanced
 * by the number of blocks in each chunk to maintain continuity.
 */
async function encryptCTR(
  key: CryptoKey,
  plaintext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / CHUNK_SIZE));
  const parts: Uint8Array[] = [];
  let blockCount = 0; // total AES blocks processed so far

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);

    // Advance the counter by blockCount to maintain continuity across chunks
    const counter = new Uint8Array(IV_SIZE);
    counter.set(iv);
    // Add blockCount to the last 8 bytes of the counter (big-endian)
    addBigUint64(counter, BigInt(blockCount));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-CTR", counter, length: 128 },
      key,
      chunk,
    );

    parts.push(new Uint8Array(encrypted));
    blockCount += Math.ceil(chunk.length / 16);
  }

  return concatUint8Arrays(parts);
}

/**
 * Decrypt AES-CTR ciphertext.
 *
 * CTR decryption is identical to encryption (XOR is symmetric).
 * We just need the same IV and counter progression.
 */
async function decryptCTR(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  // CTR is symmetric — decryption = encryption with same parameters
  return encryptCTR(key, ciphertext, iv);
}

/**
 * Add a value to the last 8 bytes of a 16-byte counter (big-endian).
 */
function addBigUint64(buf: Uint8Array, value: bigint): void {
  const view = new DataView(buf.buffer, buf.byteOffset + 8, 8);
  const current = view.getBigUint64(0);
  view.setBigUint64(0, current + value);
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

export type EncryptionMode = "CBC" | "CTR";

/**
 * Encrypt a file using AES with the specified mode.
 *
 * File format on disk:
 *   Mode(1) + Salt(16) + IV(16) + OriginalSize(8, LE) + encryptedData
 *
 * @param file      - The File to encrypt
 * @param key       - Passphrase string (any length)
 * @param mode      - "CBC" or "CTR"
 * @returns         - A Blob containing the encrypted file
 */
export async function encryptFile(
  file: File,
  key: string,
  mode: EncryptionMode,
): Promise<Blob> {
  const plaintext = new Uint8Array(await file.arrayBuffer());

  // Generate salt and IV for key derivation and encryption
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const masterKey = await deriveKey(key, salt);

  let encryptedData: Uint8Array;

  if (mode === "CBC") {
    encryptedData = await encryptCBC(masterKey, plaintext);
  } else {
    encryptedData = await encryptCTR(masterKey, plaintext, iv);
  }

  // Build the output: Mode(1) + Salt(16) + IV(16) + OrigSize(8, LE) + data
  const modeByte = new Uint8Array([mode === "CBC" ? MODE_CBC : MODE_CTR]);
  const origSize = new Uint8Array(8);
  new DataView(origSize.buffer).setBigUint64(0, BigInt(plaintext.length), true);

  const output = concatUint8Arrays([modeByte, salt, iv, origSize, encryptedData]);
  return new Blob([output]);
}

/**
 * Decrypt a file encrypted with `encryptFile`.
 *
 * Reads the mode, salt, IV, and original size from the file header,
 * derives the key, and decrypts the data. The output is truncated to
 * the original file size to ensure byte-for-byte fidelity.
 *
 * @param file - The encrypted File
 * @param key  - Passphrase string (must match the one used for encryption)
 * @param mode - "CBC" or "CTR" (must match the one used for encryption)
 * @returns    - A Blob containing the decrypted (original) file
 */
export async function decryptFile(
  file: File,
  key: string,
  mode: EncryptionMode,
): Promise<Blob> {
  const data = new Uint8Array(await file.arrayBuffer());

  // Parse header
  const modeByte = data[0];
  if ((mode === "CBC" && modeByte !== MODE_CBC) ||
      (mode === "CTR" && modeByte !== MODE_CTR)) {
    throw new Error(
      `Mode mismatch: file was encrypted with ${modeByte === MODE_CBC ? "CBC" : "CTR"}, but "${mode}" was specified.`,
    );
  }

  const salt = data.slice(1, 1 + SALT_SIZE);
  const iv = data.slice(1 + SALT_SIZE, 1 + SALT_SIZE + IV_SIZE);
  const origSize = Number(
    new DataView(data.buffer).getBigUint64(1 + SALT_SIZE + IV_SIZE, true),
  );
  const encryptedData = data.slice(1 + SALT_SIZE + IV_SIZE + 8);

  const masterKey = await deriveKey(key, salt);
  let decrypted: Uint8Array;

  if (mode === "CBC") {
    decrypted = await decryptCBC(masterKey, encryptedData);
  } else {
    decrypted = await decryptCTR(masterKey, encryptedData, iv);
  }

  // Truncate to original size (handles PKCS7 padding overflow in CBC)
  return new Blob([decrypted.slice(0, origSize)]);
}
