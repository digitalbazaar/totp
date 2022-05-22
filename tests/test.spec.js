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
  generateSecret,
  generateToken,
  verify,
  toKeyUri,
  fromKeyUri
} from '../lib/index.js';

describe('totp', () => {
  describe('generateToken', () => {
    it('should pass with default params', async () => {
      // FIXME:
    });
    it('should pass with custom params', async () => {
      // FIXME:
    });
    it('should fail with bad params', async () => {
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
});
