/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as hmac from './hmac.js';
import {default as _base32Encode} from 'base32-encode';
import {default as _base32Decode} from 'base32-decode';

// Note: RFC4648 is an alias for RFC3548 (it is the updated RFC)
const BASE32_VARIANT = 'RFC4648';

/**
 * Generates a new TOTP secret.
 *
 * @returns {Promise<string>} - Resolves to the TOTP token.
 */
export async function generateSecret() {
  const secret = await hmac.generateSecret();
  return {secret};
}

/**
 * Generates a new TOTP token to be verified by an authenticator.
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array|string} options.secret - The secret to use, as a byte
 *   array or a base32-encoded string.
 * @param {string} [options.algorithm='SHA-1'] - The hash algorithm to use;
 *   supported algorithms are: 'SHA-1', 'SHA-256', and 'SHA-512'.
 * @param {number} [options.digits=6] - The number of digits to include
 *   in the token.
 * @param {number} [options.period=30] - The number of seconds in each TOTP
 *   period; used to determine the number of TOTP steps since the current
 *   time.
 * @param {number} [options.now=Date.now()] - The current time; this should
 *   only be used for testing purposes to avoid misuse.
 *
 * @returns {Promise<object>} - Resolves to the params and TOTP token.
 */
export async function generateToken({
  secret, algorithm = 'SHA-1', digits = 6, period = 30, now = Date.now()
} = {}) {
  if(typeof digits !== 'number' || !(digits > 0 && digits <= 10)) {
    throw new Error('"digits" must be an integer > 0 and <= 10.');
  }
  secret = _decodeSecret({secret});

  // calculate the number of steps since time=0
  const steps = _getCurrentSteps({now, period});
  const token = await _generateToken({steps, algorithm, secret, digits});
  return {token, algorithm, digits, period};
}

/**
 * Verifies whether a TOTP token is authentic.
 *
 * @param {object} options - The options to use.
 * @param {string} options.token - The TOTP token to verify.
 * @param {Uint8Array|string} options.secret - The secret to use, as a byte
 *   array or a base32-encoded string.
 * @param {string} [options.algorithm='SHA-1'] - The hash algorithm to use;
 *   supported algorithms are: 'SHA-1', 'SHA-256', and 'SHA-512'.
 * @param {number} [options.period=30] - The number of seconds in each TOTP
 *   period; used to determine the number of TOTP steps since the current time.
 * @param {number} [options.delta=1] - The maximum number of steps (each step
 *   being one period in length) to allow in either direction around the
 *   current time when verifying.
 * @param {number} [options.now=Date.now()] - The current time; this should
 *   only be used for testing purposes to avoid misuse.
 *
 * @returns {Promise<string>} - Resolves to the TOTP token.
 */
export async function verify({
  token, secret, algorithm = 'SHA-1', period = 30, delta = 1, now = Date.now()
} = {}) {
  if(typeof token !== 'string') {
    throw new TypeError('"token" must be a string.');
  }
  if(!(token.length > 0 && token.length <= 10)) {
    throw new Error('"token" length must be > 0 and <= 10.');
  }
  if(typeof delta !== 'number' || !(delta >= 0 && delta <= 10)) {
    throw new Error('"delta" must be an integer >= 0 and <= 10.');
  }

  secret = _decodeSecret({secret});
  const digits = token.length;

  // hmac the token prior to comparison to mitigate timing attacks
  const verifyValue = await hmac.hmac({algorithm, secret, data: token});

  // calculate the number of steps since time=0
  const currentSteps = _getCurrentSteps({now, period});

  // note: no effort made to randomize which tokens are checked first to
  // thwart timing attacks, etc.
  const promises = [];
  for(let i = -delta; i <= delta; ++i) {
    const steps = currentSteps + i;
    promises.push(_generateVerifyValue({steps, algorithm, secret, digits}));
  }
  const candidates = await Promise.all(promises);

  // return true if any candidate matches
  return candidates.some(c => {
    for(let i = 0; i < c.length; ++i) {
      if(c[i] !== verifyValue[i]) {
        return false;
      }
    }
    return true;
  });
}

// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
export function toKeyUri({
  accountname, issuer, secret, algorithm = 'SHA-1', period = 30, digits = 6
} = {}) {
  if(!(typeof accountname === 'string' && accountname.length > 0)) {
    throw new TypeError('"accountname" must be a non-empty string.');
  }
  if(!(typeof secret === 'string' || secret instanceof Uint8Array)) {
    throw new TypeError(
      '"secret" must be Uint8Array or base32-encoded string.');
  }
  if(issuer && issuer.includes(':')) {
    issuer = encodeURIComponent(issuer);
  }
  if(accountname.includes(':')) {
    accountname = encodeURIComponent(accountname);
  }
  const label = issuer ? `${issuer}:${accountname}` : accountname;
  if(typeof secret !== 'string') {
    secret = base32Encode(secret);
  }
  const params = {secret};
  // add non-default params
  if(algorithm !== 'SHA-1') {
    params.algorithm = algorithm.replaceAll('-', '');
  }
  if(period !== 30) {
    params.period = period;
  }
  if(digits !== 6) {
    params.digits = digits;
  }
  if(issuer) {
    params.issuer = issuer;
  }
  const query = new URLSearchParams(params);
  return `otpauth://totp/${label}?${query}`;
}

export function fromKeyUri({uri} = {}) {
  const {protocol, host, pathname, searchParams} = new URL(uri);
  if(protocol !== 'otpauth:') {
    throw new Error(`Unknown protocol "${protocol}".`);
  }
  if(host !== 'totp') {
    throw new Error(`Unknown supported type "${host}".`);
  }

  const label = pathname.slice(1);
  const {
    secret, algorithm = 'SHA1', period = 30, digits = 6, issuer
  } = Object.fromEntries(searchParams);

  const [issuerPrefix, accountname] = label.split(':');
  if(!algorithm.startsWith('SHA')) {
    throw new Error(`Unsupported hash algorithm "${algorithm}".`);
  }

  return {
    type: 'totp',
    label,
    issuer,
    accountname: decodeURIComponent(accountname || issuerPrefix),
    secret,
    algorithm: `SHA-${algorithm.slice(3)}`,
    period: parseInt(period, 10),
    digits: parseInt(digits, 10)
  };
}

export function base32Encode(data) {
  return _base32Encode(data, BASE32_VARIANT, {padding: false});
}

export function base32Decode(string) {
  return _base32Decode(string, BASE32_VARIANT);
}

function _decodeSecret({secret}) {
  if(typeof secret === 'string') {
    // presume base32 encoding
    return base32Decode(secret);
  }
  if(secret instanceof Uint8Array) {
    return secret;
  }
  throw new TypeError('"secret" must be Uint8Array or base32-encoded string.');
}

// returns a 31-bit uint32 'dynamic binary code' from an hmac hash input
function _dynamicTruncation({hash}) {
  // according to RFC 4226, next we find an offset into `hash` by using the
  // last 4 bits of the last byte of `hash`
  const offset = hash[hash.length - 1] & 0x0f;

  // using the offset, we read a 31-bit uint32 (4 bytes with the most
  // significant byte masked with 0x7f; note that since the offset is a 4-bit
  // size it will be <= 16, which will not overrun the min hash size of 20
  // bytes)
  // mask first byte with 0x7f and then read integer
  hash[offset] &= 0x7f;
  const dv = new DataView(hash.buffer, hash.byteOffset, hash.length);
  return dv.getUint32(offset);
}

// generates values for verification using the double hmac mechanism to
// avoid timing attacks
async function _generateVerifyValue({steps, algorithm, secret, digits}) {
  const token = await _generateToken({steps, algorithm, secret, digits});
  return hmac.hmac({algorithm, secret, data: token});
}

async function _generateToken({steps, algorithm, secret, digits}) {
  // steps function as an 8-byte HOTP counter value per RFC 6238 and RFC 4226;
  // ensure to zero-fill to 16 hex digits to get an 8 byte value
  const counter = _hexToUint8Array(steps.toString(16).padStart(16, '0'));
  const hash = await hmac.hmac({algorithm, secret, data: counter});

  // get "dynamic binary code" per RFC 4226
  const dbc = _dynamicTruncation({hash});

  // token is `dbc % 10^<digits>`; i.e., expressing `dbc` as a zero-filled,
  // 10 digit decimal number and taking the last `digits`
  const dbcDec = dbc.toString(10).padStart(10, '0');
  return dbcDec.slice(dbcDec.length - digits);
}

function _getCurrentSteps({now, period}) {
  // convert time to seconds
  const secs = Math.floor(now / 1000);

  // calculate the number of steps since time=0
  return Math.floor(secs / period);
}

function _hexToUint8Array(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
