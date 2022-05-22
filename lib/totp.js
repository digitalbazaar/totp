/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as hmac from './hmac.js';
import base32Encode from 'base32-encode';
import base32Decode from 'base32-decode';
import { options } from 'benchmark';

export async function generateSecret({
  algorithm = 'SHA-1', digits = 6, period = 30, steps = 1
} = {}) {
  const secret = await hmac.generateSecret();
  return {algorithm, digits, period, steps, secret};
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
 *   period; used to determine the number of TOTP steps since `now`.
 * @param {number} [options.now=Date.now()] - The current time in milliseconds;
 *   used with `options.period` to determine the number of TOTP steps.
 *
 * @returns {Promise<string>} - Resolves to the TOTP token.
 */
export async function generateToken({
  secret, algorithm = 'SHA-1', digits = 6, period = 30,
  now = Date.now()
} = {}) {
  if(typeof digits !== 'number' || !(digits > 0 && digits <= 10)) {
    throw new Error('"digits" must be an integer > 0 and <= 10.');
  }
  if(typeof secret === 'string') {
    // presume base32 encoding
    secret = base32Decode(secret);
  }

  // convert time to seconds
  const secs = Math.floor(now / 1000);

  // calculate the number of steps since time=0
  const steps = Math.floor(secs / period);

  // steps function as an 8-byte HOTP counter value per RFC 6238 and RFC 4226;
  // ensure to zero-fill to 16 hex digits to get an 8 byte value
  const counter = _hexToUint8Array(steps.toString(16).padStart(16, '0'));
  const hash = await hmac.hmac({algorithm, secret, data: counter});

  // get "dynamic binary code" per RFC 4226
  const dbc = _dynamicTruncation(hash);

  // token is `dbc % 10^<digits>`; i.e., expressing `dbc` as a decimal number
  // and taking the first `dbcDec.length - digits` digits
  const dbcDec = dbc.toString(10);
  return dbcDec.slice(0, dbcDec.length - digits);
}

export async function verify({token, secret, maxSteps = 1} = {}) {
  // TODO:
}

// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
export function toKeyUri({
  secret, algorithm, period, digits, issuer
} = {}) {
  // TODO:
}

export function fromKeyUri({uri} = {}) {
  // TODO:
}

// returns a 31-bit uint32 'dynamic binary code' from an hmac hash input
function _dynamicTruncation(hash) {
  // according to RFC 4226, next we find an offset into `hash` by using the
  // last 4 bits of the last byte of `hash`
  const offset = hash[hash.length - 1] & 0x7f;

  // using the offset, we read a 31-bit uint32 (4 bytes with the most
  // significant byte masked with 0x7f; note that since the offset is a 4-bit
  // size it will be <= 16, which will not overrun the min hash size of 20
  // bytes)
  // mask first byte with 0x7f and then read integer
  hash[offset] &= 0x7f;
  const dv = new DataView(hash.buffer, hash.byteOffset, hash.length);
  return dv.getUint32(offset);
}

function _hexToUint8Array(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
