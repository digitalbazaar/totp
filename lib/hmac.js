/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {crypto} from './crypto.js';

const SUPPORTED_HASHES = ['SHA-1', 'SHA-256', 'SHA-512'];
const EXTRACTABLE = false;
const KEY_USAGE = ['sign'];

const subtle = _getCryptoSubtle();
const getRandomValues = _getRandomValues();

export async function generateSecret({size = 16} = {}) {
  return getRandomValues(new Uint8Array(size));
}

export async function hmac({algorithm, secret, data}) {
  if(!SUPPORTED_HASHES.includes(algorithm)) {
    throw new Error(`Unsupported hash algorithm "${algorithm}".`);
  }
  if(typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  const key = await subtle.importKey(
    'raw', secret, {name: 'HMAC', hash: {name: algorithm}},
    EXTRACTABLE, KEY_USAGE);
  return new Uint8Array(await subtle.sign(key.algorithm, key, data));
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
    const hash = algorithm.hash.name.toLowerCase().replaceAll('-', '');
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
