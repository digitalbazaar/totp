/*!
* Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
*/
import {default as chai} from 'chai';
const should = chai.should();

import {
  base32Encode,
  generateSecret,
  generateToken,
  verify,
  toKeyUri,
  fromKeyUri
} from '../lib/index.js';

describe('totp', () => {
  describe('generateSecret', () => {
    it('should pass with default params', async () => {
      const result = await generateSecret();
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys(['secret', 'algorithm']);
      result.algorithm.should.equal('SHA-1');
      (result.secret instanceof Uint8Array).should.equal(true);
      result.secret.length.should.equal(20);
    });
    it('should pass with SHA-1', async () => {
      const algorithm = 'SHA-1';
      const result = await generateSecret({algorithm});
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys(['secret', 'algorithm']);
      result.algorithm.should.equal('SHA-1');
      (result.secret instanceof Uint8Array).should.equal(true);
      result.secret.length.should.equal(20);
    });
    it('should pass with SHA-256', async () => {
      const algorithm = 'SHA-256';
      const result = await generateSecret({algorithm});
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys(['secret', 'algorithm']);
      result.algorithm.should.equal('SHA-256');
      (result.secret instanceof Uint8Array).should.equal(true);
      result.secret.length.should.equal(32);
    });
    it('should pass with SHA-512', async () => {
      const algorithm = 'SHA-512';
      const result = await generateSecret({algorithm});
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys(['secret', 'algorithm']);
      result.algorithm.should.equal('SHA-512');
      (result.secret instanceof Uint8Array).should.equal(true);
      result.secret.length.should.equal(64);
    });
    it('should fail with unsupported algorithm', async () => {
      let result;
      let err;
      try {
        result = await generateSecret({algorithm: 'BLAKE2b'});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('Unsupported hash algorithm "BLAKE2b".');
    });
  });

  describe('generateToken', () => {
    it('should pass with default params', async () => {
      const {secret} = await generateSecret();
      const result = await generateToken({secret});
      should.exist(result);
      result.should.be.a('object');
      result.should.include.keys(['token', 'algorithm', 'digits', 'period']);
      result.algorithm.should.equal('SHA-1');
      result.digits.should.equal(6);
      result.period.should.equal(30);
    });
    it('should pass with custom params', async () => {
      const {secret} = await generateSecret();
      const result = await generateToken({
        secret,
        algorithm: 'SHA-256',
        digits: 7,
        period: 45
      });
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys(['token', 'algorithm', 'digits', 'period']);
      result.algorithm.should.equal('SHA-256');
      result.digits.should.equal(7);
      result.period.should.equal(45);
    });
    it('should fail with no secret', async () => {
      let result;
      let err;
      try {
        result = await generateToken();
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('TypeError');
      err.message.should.equal(
        '"secret" must be Uint8Array or base32-encoded string.');
    });
    it('should fail with digits > 10', async () => {
      const {secret} = await generateSecret();
      let result;
      let err;
      try {
        result = await generateToken({secret, digits: 11});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('"digits" must be an integer > 0 and <= 10.');
    });
    it('should fail with digits < 0', async () => {
      const {secret} = await generateSecret();
      let result;
      let err;
      try {
        result = await generateToken({secret, digits: -1});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('"digits" must be an integer > 0 and <= 10.');
    });
    it('should fail with unsupported algorithm', async () => {
      const {secret} = await generateSecret();
      let result;
      let err;
      try {
        result = await generateToken({secret, algorithm: 'BLAKE2b'});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('Unsupported hash algorithm "BLAKE2b".');
    });
  });

  describe('verify', () => {
    it('should verify with default params', async () => {
      const {secret} = await generateSecret();
      const {token} = await generateToken({secret});
      const result = await verify({token, secret});
      should.exist(result);
      result.should.equal(true);
    });
    it('should not verify with default params', async () => {
      const {secret} = await generateSecret();
      let {token} = await generateToken({secret});
      token = (token[0] === '1' ? '0' : '1') + token.slice(1);
      const result = await verify({token, secret, delta: 0});
      should.exist(result);
      result.should.equal(false);
    });
    it('should verify with SHA-1', async () => {
      const algorithm = 'SHA-1';
      const {secret} = await generateSecret();
      const {token} = await generateToken({secret, algorithm});
      const result = await verify({token, secret, algorithm});
      should.exist(result);
      result.should.equal(true);
    });
    it('should not verify with SHA-1', async () => {
      const algorithm = 'SHA-1';
      const {secret} = await generateSecret();
      let {token} = await generateToken({secret, algorithm});
      token = (token[0] === '1' ? '0' : '1') + token.slice(1);
      const result = await verify({token, secret, algorithm, delta: 0});
      should.exist(result);
      result.should.equal(false);
    });
    it('should verify with SHA-256', async () => {
      const algorithm = 'SHA-256';
      const {secret} = await generateSecret();
      const {token} = await generateToken({secret, algorithm});
      const result = await verify({token, secret, algorithm});
      should.exist(result);
      result.should.equal(true);
    });
    it('should not verify with SHA-256', async () => {
      const algorithm = 'SHA-256';
      const {secret} = await generateSecret();
      let {token} = await generateToken({secret, algorithm});
      token = (token[0] === '1' ? '0' : '1') + token.slice(1);
      const result = await verify({token, secret, algorithm, delta: 0});
      should.exist(result);
      result.should.equal(false);
    });
    it('should verify with SHA-512', async () => {
      const algorithm = 'SHA-512';
      const {secret} = await generateSecret();
      const {token} = await generateToken({secret, algorithm});
      const result = await verify({token, secret, algorithm});
      should.exist(result);
      result.should.equal(true);
    });
    it('should not verify with SHA-512', async () => {
      const algorithm = 'SHA-512';
      const {secret} = await generateSecret();
      let {token} = await generateToken({secret, algorithm});
      token = (token[0] === '1' ? '0' : '1') + token.slice(1);
      const result = await verify({token, secret, algorithm, delta: 0});
      should.exist(result);
      result.should.equal(false);
    });
    it('should fail with no token', async () => {
      const {secret} = await generateSecret();
      let result;
      let err;
      try {
        result = await verify({secret});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('TypeError');
      err.message.should.equal('"token" must be a string.');
    });
    it('should fail with token length === 0', async () => {
      const {secret} = await generateSecret();
      let result;
      let err;
      try {
        result = await verify({token: '', secret});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('"token" length must be > 0 and <= 10.');
    });
    it('should fail with token length > 10', async () => {
      const {secret} = await generateSecret();
      let result;
      let err;
      try {
        result = await verify({token: '01234567891', secret});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('"token" length must be > 0 and <= 10.');
    });
    it('should fail with no secret', async () => {
      const {secret} = await generateSecret();
      const {token} = await generateToken({secret});
      let result;
      let err;
      try {
        result = await verify({token});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('TypeError');
      err.message.should.equal(
        '"secret" must be Uint8Array or base32-encoded string.');
    });
  });

  describe('toKeyUri', () => {
    it('should pass', async () => {
      const params = await generateSecret();
      const uri = toKeyUri({
        ...params,
        accountname: 'test@site.example'
      });
      const expected = 'otpauth://totp/test@site.example?secret=' +
        base32Encode(params.secret);
      expected.should.equal(uri);
    });
    it('should pass with custom params', async () => {
      const uri = toKeyUri({
        accountname: 'test@site.example',
        issuer: 'AnIssuer',
        secret: 'G4NYN7TPBY7ONUNDXIHHW4FVZI',
        algorithm: 'SHA-256',
        digits: 7,
        period: 45
      });
      const expected = 'otpauth://totp/AnIssuer:test@site.example?secret=' +
        'G4NYN7TPBY7ONUNDXIHHW4FVZI&algorithm=SHA256&period=45&digits=7' +
        '&issuer=AnIssuer';
      expected.should.equal(uri);
    });
    it('should fail without an accountname', async () => {
      const params = await generateSecret();
      delete params.secret;
      let result;
      let err;
      try {
        result = toKeyUri({
          ...params
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('TypeError');
      err.message.should.equal('"accountname" must be a non-empty string.');
    });
    it('should fail without a secret', async () => {
      let result;
      let err;
      try {
        result = toKeyUri({
          accountname: 'test@site.example'
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('TypeError');
      err.message.should.equal(
        '"secret" must be Uint8Array or base32-encoded string.');
    });
  });

  describe('fromKeyUri', () => {
    it('should pass', async () => {
      const secret = 'G4NYN7TPBY7ONUNDXIHHW4FVZI';
      const uri = `otpauth://totp/test@site.example?secret=${secret}`;
      const result = fromKeyUri({uri});
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys([
        'secret', 'algorithm', 'digits', 'period', 'accountname'
      ]);
      result.accountname.should.equal('test@site.example');
      result.algorithm.should.equal('SHA-1');
      result.digits.should.equal(6);
      result.period.should.equal(30);
      result.secret.should.equal(secret);
    });
    it('should pass with custom params', async () => {
      const secret = 'G4NYN7TPBY7ONUNDXIHHW4FVZI';
      const uri = 'otpauth://totp/AnIssuer:test@site.example?secret=' +
        'G4NYN7TPBY7ONUNDXIHHW4FVZI&algorithm=SHA256&period=45&digits=7' +
        '&issuer=AnIssuer';
      const result = fromKeyUri({uri});
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys([
        'secret', 'algorithm', 'digits', 'period', 'accountname', 'issuer'
      ]);
      result.accountname.should.equal('test@site.example');
      result.issuer.should.equal('AnIssuer');
      result.algorithm.should.equal('SHA-256');
      result.digits.should.equal(7);
      result.period.should.equal(45);
      result.secret.should.equal(secret);
    });
    it('should fail with unknown type', async () => {
      let result;
      let err;
      try {
        const uri = 'otpauth://hotp?secret=algorithm=BLAKE2b';
        result = fromKeyUri({uri});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('Unknown supported type "hotp".');
    });
    it('should fail with unknown hash algorithm', async () => {
      let result;
      let err;
      try {
        const uri = 'otpauth://totp?algorithm=BLAKE2b';
        result = fromKeyUri({uri});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.name.should.equal('Error');
      err.message.should.equal('Unsupported hash algorithm "BLAKE2b".');
    });
  });

  /* The test token shared secret uses the ASCII string value
  "12345678901234567890".  With Time Step X = 30, and the Unix epoch as
  the initial value to count time steps, where T0 = 0, the TOTP
  algorithm will display the following values for specified modes and
  timestamps.

  +-------------+--------------+------------------+----------+--------+
  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
  +-------------+--------------+------------------+----------+--------+
  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
  |             |   11:33:20   |                  |          |        |
  +-------------+--------------+------------------+----------+--------+ */
  describe('RFC 6238 Test Vectors', () => {
    // secret used with all test vectors
    const secret = new TextEncoder().encode('12345678901234567890');
    const vectors = [
      {time: 59, expectedToken: '94287082', algorithm: 'SHA-1'},
      {time: 59, expectedToken: '46119246', algorithm: 'SHA-256'},
      {time: 59, expectedToken: '90693936', algorithm: 'SHA-512'},
      {time: 1111111109, expectedToken: '07081804', algorithm: 'SHA-1'},
      {time: 1111111109, expectedToken: '68084774', algorithm: 'SHA-256'},
      {time: 1111111109, expectedToken: '25091201', algorithm: 'SHA-512'},
      {time: 1111111111, expectedToken: '14050471', algorithm: 'SHA-1'},
      {time: 1111111111, expectedToken: '67062674', algorithm: 'SHA-256'},
      {time: 1111111111, expectedToken: '99943326', algorithm: 'SHA-512'},
      {time: 1234567890, expectedToken: '89005924', algorithm: 'SHA-1'},
      {time: 1234567890, expectedToken: '91819424', algorithm: 'SHA-256'},
      {time: 1234567890, expectedToken: '93441116', algorithm: 'SHA-512'},
      {time: 2000000000, expectedToken: '69279037', algorithm: 'SHA-1'},
      {time: 2000000000, expectedToken: '90698825', algorithm: 'SHA-256'},
      {time: 2000000000, expectedToken: '38618901', algorithm: 'SHA-512'},
      {time: 20000000000, expectedToken: '65353130', algorithm: 'SHA-1'},
      {time: 20000000000, expectedToken: '77737706', algorithm: 'SHA-256'},
      {time: 20000000000, expectedToken: '47863826', algorithm: 'SHA-512'}
    ];

    for(const [i, vector] of vectors.entries()) {
      it(`should pass test vector ${i + 1}`, async () => {
        const {time, expectedToken, algorithm} = vector;
        const now = time * 1000;
        const {token} = await generateToken({
          secret, algorithm, digits: expectedToken.length, now
        });
        token.should.equal(expectedToken);
      });
    }
  });
});
