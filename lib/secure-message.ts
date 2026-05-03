import '@/polyfills/buffer';
import { generateMnemonic } from 'bip39';

/** AsyncStorage key for the encrypted payload (JSON string). */
export const MESSAGE_STORAGE_KEY = 'message';

export type EncryptedMessagePayload = {
  v: 1;
  saltPinB64: string;
  saltMnemonicB64: string;
  ivMessageB64: string;
  ivPinWrapB64: string;
  ivMnemonicWrapB64: string;
  cipherMessageB64: string;
  pinWrapB64: string;
  mnemonicWrapB64: string;
};

const PBKDF2_ITERATIONS = 150_000;

function requireSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      'Web Crypto is not available. Use https or localhost in the browser for encryption.'
    );
  }
  return subtle;
}

function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

/** Narrow `Uint8Array` for Web Crypto `BufferSource` parameters under strict TS. */
function asBufferSource(data: Uint8Array): BufferSource {
  return data as BufferSource;
}

function toBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveAesKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const subtle = requireSubtle();
  const enc = new TextEncoder();
  const keyMaterial = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: asBufferSource(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function importContentKey(raw: Uint8Array): Promise<CryptoKey> {
  const subtle = requireSubtle();
  return subtle.importKey(
    'raw',
    asBufferSource(raw),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesGcmEncrypt(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const subtle = requireSubtle();
  const buf = await subtle.encrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    key,
    asBufferSource(plaintext)
  );
  return new Uint8Array(buf);
}

async function aesGcmDecrypt(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const subtle = requireSubtle();
  const buf = await subtle.decrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    key,
    asBufferSource(ciphertext)
  );
  return new Uint8Array(buf);
}

export function isValidSixDigitPin(pin: string): boolean {
  return /^\d{6}$/.test(pin);
}

/**
 * Encrypts the message with a random content key, then wraps that key with both the PIN
 * and the BIP39 phrase so either credential can recover the message.
 */
export async function encryptAndStorePayload(
  plaintext: string,
  pin: string
): Promise<{ payload: EncryptedMessagePayload; mnemonic: string }> {
  if (!isValidSixDigitPin(pin)) {
    throw new Error('PIN must be exactly 6 digits.');
  }

  const mnemonic = generateMnemonic(128);
  const contentKeyBytes = randomBytes(32);
  const contentKey = await importContentKey(contentKeyBytes);

  const saltPin = randomBytes(16);
  const saltMnemonic = randomBytes(16);
  const ivMessage = randomBytes(12);
  const ivPinWrap = randomBytes(12);
  const ivMnemonicWrap = randomBytes(12);

  const enc = new TextEncoder();
  const messagePlain = enc.encode(plaintext);

  const cipherMessage = await aesGcmEncrypt(contentKey, ivMessage, messagePlain);

  const keyPin = await deriveAesKey(pin, saltPin);
  const keyMnemonic = await deriveAesKey(mnemonic.trim().toLowerCase(), saltMnemonic);

  const pinWrap = await aesGcmEncrypt(keyPin, ivPinWrap, contentKeyBytes);
  const mnemonicWrap = await aesGcmEncrypt(keyMnemonic, ivMnemonicWrap, contentKeyBytes);

  const payload: EncryptedMessagePayload = {
    v: 1,
    saltPinB64: toBase64(saltPin),
    saltMnemonicB64: toBase64(saltMnemonic),
    ivMessageB64: toBase64(ivMessage),
    ivPinWrapB64: toBase64(ivPinWrap),
    ivMnemonicWrapB64: toBase64(ivMnemonicWrap),
    cipherMessageB64: toBase64(cipherMessage),
    pinWrapB64: toBase64(pinWrap),
    mnemonicWrapB64: toBase64(mnemonicWrap),
  };

  return { payload, mnemonic };
}

function normalizeMnemonicInput(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).join(' ');
}

/**
 * Decrypt using either the 6-digit PIN or the full BIP39 phrase.
 */
export async function decryptPayload(
  payload: EncryptedMessagePayload,
  pinOrMnemonic: string
): Promise<string> {
  const trimmed = pinOrMnemonic.trim();
  const usePin = /^\d{6}$/.test(trimmed);

  let contentKeyBytes: Uint8Array;

  if (usePin) {
    const saltPin = fromBase64(payload.saltPinB64);
    const ivPinWrap = fromBase64(payload.ivPinWrapB64);
    const pinWrap = fromBase64(payload.pinWrapB64);
    const keyPin = await deriveAesKey(trimmed, saltPin);
    contentKeyBytes = await aesGcmDecrypt(keyPin, ivPinWrap, pinWrap);
  } else {
    const phrase = normalizeMnemonicInput(trimmed);
    const saltMnemonic = fromBase64(payload.saltMnemonicB64);
    const ivMnemonicWrap = fromBase64(payload.ivMnemonicWrapB64);
    const mnemonicWrap = fromBase64(payload.mnemonicWrapB64);
    const keyMnemonic = await deriveAesKey(phrase, saltMnemonic);
    contentKeyBytes = await aesGcmDecrypt(keyMnemonic, ivMnemonicWrap, mnemonicWrap);
  }

  const contentKey = await importContentKey(contentKeyBytes);
  const ivMessage = fromBase64(payload.ivMessageB64);
  const cipherMessage = fromBase64(payload.cipherMessageB64);
  const plain = await aesGcmDecrypt(contentKey, ivMessage, cipherMessage);
  return new TextDecoder().decode(plain);
}

export function parsePayloadJson(json: string): EncryptedMessagePayload {
  const data = JSON.parse(json) as EncryptedMessagePayload;
  if (data.v !== 1) {
    throw new Error('Unsupported payload version.');
  }
  return data;
}
