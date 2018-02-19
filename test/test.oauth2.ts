/**
 * Copyright 2018 Google LLC. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import axios from 'axios';
import * as qs from 'querystring';
import * as sinon from 'sinon';
import * as test from 'tape';
import * as url from 'url';

import {OAuth2Client} from '../src';
import * as crypto from '../src/crypto';
import {CodeChallengeMethod, JWK, JWKS} from '../src/interfaces';
import {LoginTicket} from '../src/loginticket';

const clientId = 'CLIENT_ID';
const clientSecret = 'CLIENT_SECRET';
const redirectUri = 'REDIRECT';
const ACCESS_TYPE = 'offline';
const SCOPE = 'scopex';
const SCOPE_ARRAY = ['scopex', 'scopey'];

const privateKey: JWK = require('../../test/fixtures/private.json');
const publicKey: JWK = require('../../test/fixtures/public.json');
const publicKeys: JWKS = {
  keys: [publicKey]
};

test('should generate a valid consent page url', t => {
  const opts = {
    access_type: ACCESS_TYPE,
    scope: SCOPE,
    response_type: 'code token'
  };
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl(opts);
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.response_type, 'code token');
  t.equal(query.access_type, ACCESS_TYPE);
  t.equal(query.scope, SCOPE);
  t.equal(query.client_id, clientId);
  t.equal(query.redirect_uri, redirectUri);
  t.end();
});

test(
    'should throw an error if generateAuthUrl is called with invalid parameters',
    t => {
      const opts = {
        access_type: ACCESS_TYPE,
        scope: SCOPE,
        code_challenge_method: CodeChallengeMethod.S256
      };

      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      try {
        client.generateAuthUrl(opts);
      } catch (e) {
        t.equal(
            e.message,
            'If a code_challenge_method is provided, code_challenge must be included.');
        t.end();
      }
    });

test(
    'should generate a valid code verifier and resulting challenge',
    async t => {
      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      const codes = await client.generateCodeVerifier();
      // ensure the code_verifier matches all requirements
      t.equal(codes.codeVerifier.length, 128);
      const match = codes.codeVerifier.match(/[a-zA-Z0-9\-\.~_]*/);
      t.true(match);
      if (!match) return;
      t.true(match.length > 0 && match[0] === codes.codeVerifier);
      t.end();
    });

test('should include code challenge and method in the url', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const codes = await client.generateCodeVerifier();
  const authUrl = client.generateAuthUrl({
    code_challenge: codes.codeChallenge,
    code_challenge_method: CodeChallengeMethod.S256
  });
  const parsed = url.parse(authUrl);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const props = qs.parse(parsed.query);
  t.equal(props.code_challenge, codes.codeChallenge);
  t.equal(props.code_challenge_method, CodeChallengeMethod.S256);
  t.end();
});

test('should verifyIdToken properly', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const idToken = 'idToken';
  const audience = 'fakeAudience';
  const maxExpiry = 5;
  const payload =
      {aud: 'aud', sub: 'sub', iss: 'iss', iat: 1514162443, exp: 1514166043};
  const header = {alg: 'foo', typ: 'bar', kid: 'tycho'};

  client.getFederatedSignonCerts = async () => {
    return publicKeys;
  };

  client.verifySignedJwtWithCerts = async (
      jwt: string, certs: {}, requiredAudience: string|string[],
      issuers?: string[], theMaxExpiry?: number) => {
    t.equal(jwt, idToken);
    t.deepEqual(certs, publicKeys);
    t.equal(requiredAudience, audience);
    t.equal(theMaxExpiry, maxExpiry);
    return new LoginTicket(header, payload);
  };
  const result = await client.verifyIdToken({idToken, audience, maxExpiry});
  t.notEqual(result, null);
  t.equal(result.header, header);
  t.equal(result.payload, payload);
  t.end();
});

test(
    'should provide a reasonable error in verifyIdToken with wrong parameters',
    async t => {
      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      const fakeCerts = {a: 'a', b: 'b'};
      const idToken = 'idToken';
      const audience = 'fakeAudience';
      const header = {alg: 'foo', typ: 'bar', kid: 'kepler'};
      const payload = {
        aud: 'aud',
        sub: 'sub',
        iss: 'iss',
        iat: 1514162443,
        exp: 1514166043
      };
      client.verifySignedJwtWithCerts = async (
          jwt: string, certs: {}, requiredAudience: string|string[],
          issuers?: string[], theMaxExpiry?: number) => {
        t.equal(jwt, idToken);
        t.deepEqual(certs, fakeCerts);
        t.equal(requiredAudience, audience);
        return new LoginTicket(header, payload);
      };
      try {
        // tslint:disable-next-line no-any
        await (client as any).verifyIdToken(idToken, audience);
      } catch (e) {
        t.equal(
            e.message,
            'This method accepts an options object as the first parameter, which includes the idToken, audience, and maxExpiry.');
        t.end();
      }
    });

test('should allow scopes to be specified as array', t => {
  const opts = {
    access_type: ACCESS_TYPE,
    scope: SCOPE_ARRAY,
    response_type: 'code token'
  };
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl(opts);
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.scope, SCOPE_ARRAY.join(' '));
  t.end();
});

test(
    'should set response_type param to code if none is given while' +
        'generating the consent page url',
    t => {
      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      const generated = client.generateAuthUrl();
      const parsed = url.parse(generated);
      if (typeof parsed.query !== 'string') {
        throw new Error('Unable to parse querystring');
      }
      const query = qs.parse(parsed.query);
      t.equal(query.response_type, 'code');
      t.end();
    });

test.only('should verify a valid certificate against a jwt', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});
  let data = Buffer.from(header).toString('base64') + '.' +
      Buffer.from(idToken).toString('base64');
  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const login =
      await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  t.equal(login.getUserId(), '123456789');
  t.end();
});

test('should fail due to invalid audience', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'wrongaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Wrong recipient'), 0);
    t.end();
  }
});

test('should fail due to invalid array of audiences', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'wrongaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;
  const validAudiences = ['testaudience', 'extra-audience'];
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, validAudiences);
  } catch (e) {
    t.equal(e.message.indexOf('Wrong recipient'), 0);
    t.end();
  }
});

test('should fail due to invalid signature', async t => {
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: 1393241597,
    exp: 1393245497
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});
  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');
  const signature = await crypto.getSignature(data, privateKey);
  // Originally: data += '.'+signature;
  data += signature;
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Wrong number of segments'), 0);
    t.end();
  }
});

test('should fail due to invalid header', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });

  // Make the header invalid JSON by slicing it
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'}).slice(2);
  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');
  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Can\'t parse token header'), 0);
    t.end();
  }
});

test('should fail due to invalid payload', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  // Create an invalid payload by slicing the stringified json
  const idToken = JSON.stringify({
                        iss: 'testissuer',
                        aud: 'testaudience',
                        azp: 'testauthorisedparty',
                        email_verified: true,
                        id: '123456789',
                        sub: '123456789',
                        email: 'test@test.com',
                        iat: now,
                        exp: expiry
                      })
                      .slice(2);  // <---
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});
  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');
  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Can\'t parse token payload'), 0);
    t.end();
  }
});

test('should fail due to invalid signature', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});
  const data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64') + '.' +
      'broken-signature';
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Invalid token signature'), 0);
    t.end();
  }
});

test('should fail due to no expiration date', async t => {
  const now = new Date().getTime() / 1000;
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: 'true',
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});
  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');
  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('No expiration time'), 0);
    t.end();
  }
});

test('should fail due to no issue time', async t => {
  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: 'true',
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});
  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');
  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('No issue time'), 0);
    t.end();
  }
});

test(
    'should fail due to certificate with expiration date in future',
    async t => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + (2 * maxLifetimeSecs);
      const idToken = JSON.stringify({
        iss: 'testissuer',
        aud: 'testaudience',
        azp: 'testauthorisedparty',
        email_verified: true,
        id: '123456789',
        sub: '123456789',
        email: 'test@test.com',
        iat: now,
        exp: expiry
      });
      const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

      let data = new Buffer(header).toString('base64') + '.' +
          new Buffer(idToken).toString('base64');

      const signature = await crypto.getSignature(data, privateKey);

      data += '.' + signature;

      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      try {
        await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
      } catch (e) {
        t.equal(e.message.indexOf('Expiration time too far in future'), 0);
        t.end();
      }
    });

test(
    'should pass due to expiration date in future with adjusted max expiry',
    async t => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + (2 * maxLifetimeSecs);
      const maxExpiry = (3 * maxLifetimeSecs);
      const idToken = JSON.stringify({
        iss: 'testissuer',
        aud: 'testaudience',
        azp: 'testauthorisedparty',
        email_verified: true,
        id: '123456789',
        sub: '123456789',
        email: 'test@test.com',
        iat: now,
        exp: expiry
      });
      const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

      let data = new Buffer(header).toString('base64') + '.' +
          new Buffer(idToken).toString('base64');

      const signature = await crypto.getSignature(data, privateKey);

      data += '.' + signature;

      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      await client.verifySignedJwtWithCerts(
          data, publicKeys, 'testaudience', ['testissuer'], maxExpiry);
      t.end();
    });

test('should fail due to token being used too early', async t => {
  const maxLifetimeSecs = 86400;
  const clockSkews = 300;
  const now = (new Date().getTime() / 1000);
  const expiry = now + (maxLifetimeSecs / 2);
  const issueTime = now + (clockSkews * 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: issueTime,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signature = await crypto.getSignature(data, privateKey);

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Token used too early'), 0);
    t.end();
  }
});

test('should fail due to token being used too late', async t => {
  const maxLifetimeSecs = 86400;
  const clockSkews = 300;
  const now = (new Date().getTime() / 1000);
  const expiry = now - (maxLifetimeSecs / 2);
  const issueTime = now - (clockSkews * 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: issueTime,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signature = await crypto.getSignature(data, privateKey);

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(data, publicKeys, 'testaudience');
  } catch (e) {
    t.equal(e.message.indexOf('Token used too late'), 0);
    t.end();
  }
});

test('should fail due to invalid issuer', async t => {
  const maxLifetimeSecs = 86400;
  const now = (new Date().getTime() / 1000);
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'invalidissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: true,
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signature = await crypto.getSignature(data, privateKey);
  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.verifySignedJwtWithCerts(
        data, publicKeys, 'testaudience', ['testissuer']);
  } catch (e) {
    t.equal(e.message.indexOf('Invalid issuer'), 0);
    t.end();
  }
});

test('should pass due to valid issuer', async t => {
  const maxLifetimeSecs = 86400;
  const now = (new Date().getTime() / 1000);
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = JSON.stringify({
    iss: 'testissuer',
    aud: 'testaudience',
    azp: 'testauthorisedparty',
    email_verified: 'true',
    id: '123456789',
    sub: '123456789',
    email: 'test@test.com',
    iat: now,
    exp: expiry
  });
  const header = JSON.stringify({kid: 'keyid', alg: 'RS256'});

  let data = new Buffer(header).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signature = await crypto.getSignature(data, privateKey);

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  await client.verifySignedJwtWithCerts(
      data, publicKeys, 'testaudience', ['testissuer']);
  t.end();
});

test('should be able to retrieve a list of Google certificates', async t => {
  const sandbox = sinon.sandbox.create();
  const stub =
      sandbox.stub(axios, 'get')
          .withArgs('https://www.googleapis.com/oauth2/v3/certs')
          .returns({
            status: 200,
            data: publicKeys,
            headers: {
              'Cache-Control':
                  'public, max-age=23641, must-revalidate, no-transform',
              'Content-Type': 'application/json'
            }
          });
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const certs = await client.getFederatedSignonCerts();
  t.equal(stub.callCount, 1);
  t.equal(certs.keys.length, 1);
  t.notEqual(certs.keys[0], null);
  sandbox.restore();
  t.end();
});

test(
    'should be able to retrieve a list of Google certificates from cache again',
    async t => {
      const sandbox = sinon.sandbox.create();
      const stub =
          sandbox.stub(axios, 'get')
              .withArgs('https://www.googleapis.com/oauth2/v3/certs')
              .returns({
                status: 200,
                data: publicKeys,
                headers: {
                  'cache-control':
                      'public, max-age=23641, must-revalidate, no-transform',
                  'content-type': 'application/json'
                }
              });
      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      const certs = await client.getFederatedSignonCerts();
      t.equal(certs.keys.length, 1);
      const certs2 = await client.getFederatedSignonCerts();
      t.equal(stub.callCount, 1);
      t.equal(certs2.keys.length, 1);
      sandbox.restore();
      t.end();
    });

test('should set redirect_uri if not provided in options', t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl();
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    return t.fail('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.redirect_uri, redirectUri);
  t.end();
});

test('should set client_id if not provided in options', t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl({});
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.client_id, clientId);
  t.end();
});

test('should override redirect_uri if provided in options', t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl({redirect_uri: 'overridden'});
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.redirect_uri, 'overridden');
  t.end();
});

test('should override client_id if provided in options', t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl({client_id: 'client_override'});
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.client_id, 'client_override');
  t.end();
});

test('should return error in callback on request', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.request({});
  } catch (e) {
    t.equal(e.message, 'No access, or refresh token is set.');
    t.end();
  }
});

test('should return error in callback on refreshAccessToken', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  try {
    await client.refreshAccessToken();
  } catch (e) {
    t.equal(e.message, 'No refresh token available.');
    t.end();
  }
});

function mockToken() {
  const sandbox = sinon.sandbox.create();
  const stubs = [
    sandbox.stub(axios, 'post')
        .withArgs(
            'https://www.googleapis.com/oauth2/v4/token', sinon.match.string,
            {headers: {'Content-Type': 'application/x-www-form-urlencoded'}})
        .returns({status: 200, data: {access_token: 'abc123', expires_in: 1}}),
    sandbox.stub(axios, 'request')
        .withArgs({
          url: 'http://example.com',
          headers: {Authorization: sinon.match.string}
        })
        .returns({status: 200})
  ];
  return {sandbox, stubs};
}

test('should refresh token if missing access token', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {refresh_token: 'refresh-token-placeholder'};
  const {sandbox, stubs} = mockToken();
  await client.request('http://example.com');
  stubs.forEach(s => t.equal(s.callCount, 1));
  t.equal('abc123', client.credentials.access_token);
  sandbox.restore();
  t.end();
});

test('should refresh if access token is expired', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'refresh-token-placeholder',
    expiry_date: (new Date()).getTime() - 1000
  };
  const {sandbox, stubs} = mockToken();
  await client.request({url: 'http://example.com'});
  stubs.forEach(s => t.equal(s.callCount, 1));
  t.equal('abc123', client.credentials.access_token);
  sandbox.restore();
  t.end();
});

test(
    'should refresh if access token will expired soon and time to refresh' +
        ' before expiration is set',
    async t => {
      const eagerRefreshThresholdMillis = 5000;
      const client = new OAuth2Client(
          {clientId, clientSecret, redirectUri, eagerRefreshThresholdMillis});
      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: (new Date()).getTime() + 3000
      };
      const {sandbox, stubs} = mockToken();
      await client.request({url: 'http://example.com'});
      stubs.forEach(s => t.equal(s.callCount, 1));
      t.equal('abc123', client.credentials.access_token);
      sandbox.restore();
      t.end();
    });

test(
    'should not refresh if access token will not expire soon and time to refresh before expiration is set',
    async t => {
      const eagerRefreshThresholdMillis = 5000;
      const client = new OAuth2Client(
          {clientId, clientSecret, redirectUri, eagerRefreshThresholdMillis});

      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: (new Date()).getTime() + 10000,
      };
      const {sandbox, stubs} = mockToken();
      await client.request({url: 'http://example.com'});
      t.false(stubs[0].called);
      t.equal(stubs[1].callCount, 1);
      t.equal('initial-access-token', client.credentials.access_token);
      sandbox.restore();
      t.end();
    });

test('should not refresh if not expired', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'refresh-token-placeholder',
    expiry_date: (new Date()).getTime() + 500000
  };
  const {sandbox, stubs} = mockToken();
  await client.request({url: 'http://example.com'});
  t.false(stubs[0].called);
  t.equal(stubs[1].callCount, 1);
  sandbox.restore();
  t.equal('initial-access-token', client.credentials.access_token);
  t.end();
});

test('should assume access token is not expired', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'refresh-token-placeholder'
  };
  const {sandbox, stubs} = mockToken();
  await client.request({url: 'http://example.com'});
  t.equal('initial-access-token', client.credentials.access_token);
  t.false(stubs[0].called);
  t.equal(stubs[1].callCount, 1);
  sandbox.restore();
  t.end();
});

test('should revoke credentials if access token present', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {access_token: 'abc', refresh_token: 'abc'};
  const sandbox = sinon.sandbox.create();
  const stub = sandbox.stub(client, 'revokeToken').withArgs('abc').returns({
    data: {success: true}
  });
  const res = await client.revokeCredentials();
  t.equal(stub.callCount, 1);
  t.equal(res.data!.success, true);
  t.equal(JSON.stringify(client.credentials), '{}');
  sandbox.restore();
  t.end();
});

test(
    'should clear credentials and return error if no access token to revoke',
    async t => {
      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      client.credentials = {refresh_token: 'abc'};
      try {
        await client.revokeCredentials();
      } catch (e) {
        t.equal(e.message, 'No access token to revoke.');
        t.equal(JSON.stringify(client.credentials), '{}');
        t.end();
      }
    });

test('should allow a code_verifier to be passed', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const sandbox = sinon.sandbox.create();
  const stub =
      sandbox.stub(axios, 'post')
          .withArgs(
              'https://www.googleapis.com/oauth2/v4/token',
              sinon.match(/code_verifier=its_verified/),
              {headers: {'Content-Type': 'application/x-www-form-urlencoded'}})
          .returns({
            data: {access_token: 'abc', refresh_token: '123', expires_in: 10}
          });
  const res =
      await client.getToken({code: 'code here', codeVerifier: 'its_verified'});
  t.equal(stub.callCount, 1);
  sandbox.restore();
  t.end();
});

test('should return expiry_date', async t => {
  const now = (new Date()).getTime();
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const sandbox = sinon.sandbox.create();
  const stub =
      sandbox.stub(axios, 'post')
          .withArgs(
              'https://www.googleapis.com/oauth2/v4/token', sinon.match.string,
              {headers: {'Content-Type': 'application/x-www-form-urlencoded'}})
          .returns({
            data: {access_token: 'abc', refresh_token: '123', expires_in: 10}
          });
  const tokens = await client.getToken({code: 'code here'});
  t.true(tokens.expiry_date! >= now + (10 * 1000));
  t.true(tokens.expiry_date! <= now + (15 * 1000));
  t.equal(stub.callCount, 1);
  sandbox.restore();
  t.end();
});
