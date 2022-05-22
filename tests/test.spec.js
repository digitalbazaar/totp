/*!
* Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
*/
import {
  default as chai,
  expect
} from 'chai';
import {default as chaiBytes} from 'chai-bytes';
chai.use(chaiBytes);
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
    it('should pass', async () => {
      const result = await generateSecret();
      should.exist(result);
      result.should.be.an('object');
      result.should.include.keys(['secret']);
      (result.secret instanceof Uint8Array).should.equal(true);
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
    it('should verify a TOTP token', async () => {
      // FIXME:
    });
    it('should reject an invalid TOTP token', async () => {
      // FIXME:
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
      err.message.should.equal('"secret" must be a string or Uint8Array.');
    });
  });

  describe('fromKeyUri', () => {
    // it('should pass', async () => {
    //   const params = await generateSecret();
    //   toKeyUri({
    //     ...params,
    //     accountname: 'test@site.example'
    //   });
    //   // FIXME:
    // });
    // it('should pass with custom params', async () => {
    //   const params = await generateSecret();
    //   toKeyUri({
    //     ...params,
    //     accountname: 'test@site.example'
    //   });
    //   // FIXME:
    // });
    it('should fail without an accountname', async () => {
      // FIXME:
    });
    it('should fail with unknown type', async () => {
      // FIXME:
    });
    it('should fail with unknown hash algorithm', async () => {
      // FIXME:
    });
  });
});
