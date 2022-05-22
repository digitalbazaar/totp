/*!
* Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
*/
import Benchmark from 'benchmark';

const suite = new Benchmark.Suite();

import {
  generateSecret, generateToken
} from '../lib/index.js';

suite
  .add('generateToken', {
    defer: true,
    fn: async deferred => {
      // FIXME:
      const params = await generateSecret();
      await generateToken(params);
      deferred.resolve();
    }
  })
  .on('cycle', event => {
    console.log(String(event.target));
  })
  .on('complete', function() {
    console.log('Fastest is ' + this.filter('fastest').map('name'));
  })
  .run();
