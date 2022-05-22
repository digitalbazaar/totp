/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {crypto} from './crypto.js';

export const SUPPORTED_HASHES = ['SHA-1', 'SHA-256', 'SHA-512'];

// TOTP secrets are padded to digest size by repeating the secret
// SHA-1: 20 bytes
// SHA-256: 32 bytes
// SHA-512: 64 bytes
export const MIN_SECRET_SIZE = new Map([
  ['SHA-1', 20],
  ['SHA-256', 32],
  ['SHA-512', 64],
]);

const EXTRACTABLE = false;
const KEY_USAGE = ['sign'];

const subtle = _getCryptoSubtle();
const getRandomValues = _getRandomValues();

export async function generateSecret({size = 20} = {}) {
  return getRandomValues(new Uint8Array(size));
}

// TOTP hmac will pad secret to algorithm size per RFC 6238
export async function hmac({algorithm, secret, data}) {
  if(!SUPPORTED_HASHES.includes(algorithm)) {
    throw new Error(`Unsupported hash algorithm "${algorithm}".`);
  }
  if(typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  // pad secret according to RFC 6238
  secret = _padSecret({algorithm, secret});
  const hmacAlgorithm = {
    name: 'HMAC', hash: {name: algorithm}, length: secret.length * 8
  };
  const key = await subtle.importKey(
    'raw', secret, hmacAlgorithm, EXTRACTABLE, KEY_USAGE);
  return new Uint8Array(await subtle.sign(key.algorithm, key, data));
}

// TOTP secrets are padded by repeating the secret if insufficient in length
function _padSecret({algorithm, secret}) {
  const minSize = MIN_SECRET_SIZE.get(algorithm);
  if(secret.length >= minSize) {
    return secret;
  }
  const padded = new Uint8Array(minSize);
  let length = 0;
  while(length < minSize) {
    const remaining = minSize - length;
    if(secret.length > remaining) {
      padded.set(secret.subarray(0, remaining), length);
      break;
    }
    padded.set(secret, length);
    length += secret.length;
  }
  return padded;
}

function _getCryptoSubtle() {
  const subtle = crypto?.webcrypto?.subtle ?? crypto?.subtle ?? {};
  if(subtle.importKey) {
    return subtle;
  }

  // local node.js 14.x polyfill supports just `hmac`
  subtle.importKey = async function importKey(format, secret, algorithm) {
    return {format, secret, algorithm};
  };
  subtle.sign = async function sign(algorithm, key, data) {
    const {secret} = key;
    const hash = algorithm.hash.name.toLowerCase().replace(/-/g, '');
    const hmac = crypto.createHmac(hash, secret).update(data).digest();
    return new Uint8Array(hmac);
  };

  return subtle;
}

function _getRandomValues() {
  if(crypto?.getRandomValues) {
    return crypto.getRandomValues.bind(crypto);
  }

  if(crypto?.webcrypto?.getRandomValues) {
    return crypto.webcrypto.getRandomValues.bind(crypto.webcrypto);
  }

  if(crypto.randomFill) {
    return async function randomFill(x) {
      return new Promise((resolve, reject) =>
        crypto.randomFill(
          x, (err, result) => err ? reject(err) : resolve(result)));
    };
  }

  throw new Error(
    'Web Crypto "getRandomValues" or "crypto.randomFill" required.');
}
