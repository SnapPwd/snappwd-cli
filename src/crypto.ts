import { webcrypto } from 'node:crypto';

const crypto = webcrypto as unknown as Crypto;

const KEY_SIZE_V1 = 16; // AES-128 (legacy)
const KEY_SIZE_V2 = 32; // AES-256 (new)
const IV_SIZE = 12;
const VERSION_V1 = 1;
const VERSION_V2 = 2;

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Precomputed lookup table for O(1) character-to-value conversion
const BASE58_MAP: Record<string, number> = {};
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP[BASE58_ALPHABET[i]] = i;
}

/**
 * Encode a Uint8Array to base58 string
 */
export function base58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (let b = 0; b < bytes.length; b++) {
    let carry = bytes[b];
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  // Handle leading zeros
  let result = "";
  for (let b = 0; b < bytes.length; b++) {
    if (bytes[b] === 0) result += BASE58_ALPHABET[0];
    else break;
  }
  // Convert digits to base58 characters (reverse order)
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

/**
 * Decode a base58 string to Uint8Array
 */
export function base58Decode(str: string): Uint8Array {
  const bytes = [0];
  for (let c = 0; c < str.length; c++) {
    const value = BASE58_MAP[str[c]];
    if (value === undefined) throw new Error("Invalid base58 character");
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Handle leading '1's (zeros in base58)
  const leadingOnes = str.match(/^1*/)?.[0].length || 0;
  const result = new Uint8Array(leadingOnes + bytes.length);
  // Leading zeros
  for (let i = 0; i < leadingOnes; i++) {
    result[i] = 0;
  }
  // Reverse bytes into result
  for (let i = 0; i < bytes.length; i++) {
    result[leadingOnes + i] = bytes[bytes.length - 1 - i];
  }
  return result;
}

/**
 * Generate a random encryption key
 */
export function generateEncryptionKey(): string {
  const array = new Uint8Array(KEY_SIZE_V2);
  crypto.getRandomValues(array);
  return base58Encode(array);
}

/**
 * Encrypt data with AES using the Web Crypto API
 */
export async function encryptData(
  plaintext: string,
  key: string
): Promise<string> {
  const keyData = base58Decode(key);
  const keySize = keyData.length;
  const version = keySize === KEY_SIZE_V2 ? VERSION_V2 : VERSION_V1;

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(plaintext);

  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    encodedData as unknown as BufferSource
  );

  // New format: [version | IV | ciphertext]
  const result = new Uint8Array(1 + iv.length + encryptedData.byteLength);
  result[0] = version;
  result.set(iv, 1);
  result.set(new Uint8Array(encryptedData), 1 + iv.length);

  return Buffer.from(result).toString('base64');
}

/**
 * Decrypt data with AES using the Web Crypto API
 */
export async function decryptData(
  encryptedBase64: string,
  key: string
): Promise<string> {
  const keyData = base58Decode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const encryptedData = new Uint8Array(Buffer.from(encryptedBase64, 'base64'));
  
  let iv: Uint8Array;
  let ciphertext: Uint8Array;

  // Detect format: versioned (first byte is VERSION_V1 or VERSION_V2) or legacy
  if (encryptedData[0] === VERSION_V1 || encryptedData[0] === VERSION_V2) {
    // Versioned format: [version | IV | ciphertext]
    iv = encryptedData.slice(1, 1 + IV_SIZE);
    ciphertext = encryptedData.slice(1 + IV_SIZE);
  } else {
    // Legacy format: [IV | ciphertext]
    iv = encryptedData.slice(0, IV_SIZE);
    ciphertext = encryptedData.slice(IV_SIZE);
  }

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    ciphertext as unknown as BufferSource
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}

/**
 * Encrypt file data (Buffer/Uint8Array)
 */
export async function encryptFileBuffer(
  buffer: Buffer,
  key: string
): Promise<{ iv: Uint8Array; encryptedData: ArrayBuffer }> {
  const keyData = base58Decode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));

  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    buffer as unknown as BufferSource
  );

  return { iv, encryptedData };
}

/**
 * Decrypt file data
 */
export async function decryptFileBuffer(
  iv: Uint8Array,
  encryptedData: ArrayBuffer,
  key: string
): Promise<Buffer> {
  const keyData = base58Decode(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    encryptedData as unknown as BufferSource
  );

  return Buffer.from(decryptedData);
}
