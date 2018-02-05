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

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as nock from 'nock';
import {Scope} from 'nock';
import * as path from 'path';
import * as qs from 'querystring';
import * as test from 'tape';
import {Test} from 'tape';
import * as url from 'url';

import {OAuth2Client} from '../src';
import {CodeChallengeMethod} from '../src/interfaces';
import {LoginTicket} from '../src/loginticket';

nock.disableNetConnect();

const clientId = 'CLIENT_ID';
const clientSecret = 'CLIENT_SECRET';
const redirectUri = 'REDIRECT';
const ACCESS_TYPE = 'offline';
const SCOPE = 'scopex';
const SCOPE_ARRAY = ['scopex', 'scopey'];

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

test('should generate a valid code verifier and resulting challenge', t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const codes = client.generateCodeVerifier();
  // ensure the code_verifier matches all requirements
  t.equal(codes.codeVerifier.length, 128);
  const match = codes.codeVerifier.match(/[a-zA-Z0-9\-\.~_]*/);
  t.true(match);
  if (!match) return;
  t.true(match.length > 0 && match[0] === codes.codeVerifier);
  t.end();
});

test('should include code challenge and method in the url', t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const codes = client.generateCodeVerifier();
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
  const fakeCerts = {a: 'a', b: 'b'};
  const idToken = 'idToken';
  const audience = 'fakeAudience';
  const maxExpiry = 5;
  const payload =
      {aud: 'aud', sub: 'sub', iss: 'iss', iat: 1514162443, exp: 1514166043};
  const scope = nock('https://www.googleapis.com')
                    .get('/oauth2/v1/certs')
                    .reply(200, fakeCerts);
  client.verifySignedJwtWithCerts =
      (jwt: string, certs: {}, requiredAudience: string|string[],
       issuers?: string[], theMaxExpiry?: number) => {
        t.equal(jwt, idToken);
        t.equal(JSON.stringify(certs), JSON.stringify(fakeCerts));
        t.equal(requiredAudience, audience);
        t.equal(theMaxExpiry, maxExpiry);
        return new LoginTicket('c', payload);
      };
  const result = await client.verifyIdToken({idToken, audience, maxExpiry});
  t.assert(scope.isDone());
  t.notEqual(result, null);
  t.equal(result.envelope, 'c');
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
      const payload = {
        aud: 'aud',
        sub: 'sub',
        iss: 'iss',
        iat: 1514162443,
        exp: 1514166043
      };
      client.verifySignedJwtWithCerts =
          (jwt: string, certs: {}, requiredAudience: string|string[],
           issuers?: string[], theMaxExpiry?: number) => {
            t.equal(jwt, idToken);
            t.equal(JSON.stringify(certs), JSON.stringify(fakeCerts));
            t.equal(requiredAudience, audience);
            return new LoginTicket('c', payload);
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

test('should verify a valid certificate against a jwt', t => {
  t.plan(1);
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const login =
      client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');

  t.equal(login.getUserId(), '123456789');
});

test('should fail due to invalid audience', t => {
  t.plan(1);
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"wrongaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Wrong recipient/);
});

test('should fail due to invalid array of audiences', t => {
  t.plan(1);
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"wrongaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const validAudiences = ['testaudience', 'extra-audience'];
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, validAudiences);
  }, /Wrong recipient/);
});

test('should fail due to invalid signature', t => {
  t.plan(1);
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":1393241597,' +
      '"exp":1393245497' +
      '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  // Originally: data += '.'+signature;
  data += signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Wrong number of segments/);
});

test('should fail due to invalid envelope', t => {
  t.plan(1);
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid"' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Can\'t parse token envelope/);
});

test('should fail due to invalid payload', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer"' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Can\'t parse token payload/);
  t.end();
});

test('should fail due to invalid signature', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  const data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64') + '.' +
      'broken-signature';

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Invalid token signature/);
  t.end();
});

test('should fail due to no expiration date', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const now = new Date().getTime() / 1000;

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /No expiration time/);
  t.end();
});

test('should fail due to no issue time', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (maxLifetimeSecs / 2);

  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /No issue time/);
  t.end();
});

test('should fail due to certificate with expiration date in future', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = new Date().getTime() / 1000;
  const expiry = now + (2 * maxLifetimeSecs);
  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Expiration time too far in future/);
  t.end();
});

test(
    'should pass due to expiration date in future with adjusted max expiry',
    t => {
      const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
      const privateKey =
          fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + (2 * maxLifetimeSecs);
      const maxExpiry = (3 * maxLifetimeSecs);
      const idToken = '{' +
          '"iss":"testissuer",' +
          '"aud":"testaudience",' +
          '"azp":"testauthorisedparty",' +
          '"email_verified":"true",' +
          '"id":"123456789",' +
          '"sub":"123456789",' +
          '"email":"test@test.com",' +
          '"iat":' + now + ',' +
          '"exp":' + expiry + '}';
      const envelope = '{' +
          '"kid":"keyid",' +
          '"alg":"RS256"' +
          '}';

      let data = new Buffer(envelope).toString('base64') + '.' +
          new Buffer(idToken).toString('base64');

      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');

      data += '.' + signature;

      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      client.verifySignedJwtWithCerts(
          data, {keyid: publicKey}, 'testaudience', ['testissuer'], maxExpiry);
      t.end();
    });

test('should fail due to token being used to early', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const clockSkews = 300;
  const now = (new Date().getTime() / 1000);
  const expiry = now + (maxLifetimeSecs / 2);
  const issueTime = now + (clockSkews * 2);
  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + issueTime + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Token used too early/);
  t.end();
});

test('should fail due to token being used to late', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const clockSkews = 300;
  const now = (new Date().getTime() / 1000);
  const expiry = now - (maxLifetimeSecs / 2);
  const issueTime = now - (clockSkews * 2);
  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + issueTime + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(data, {keyid: publicKey}, 'testaudience');
  }, /Token used too late/);
  t.end();
});

test('should fail due to invalid issuer', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = (new Date().getTime() / 1000);
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = '{' +
      '"iss":"invalidissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  t.throws(() => {
    client.verifySignedJwtWithCerts(
        data, {keyid: publicKey}, 'testaudience', ['testissuer']);
  }, /Invalid issuer/);
  t.end();
});

test('should pass due to valid issuer', t => {
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  const maxLifetimeSecs = 86400;
  const now = (new Date().getTime() / 1000);
  const expiry = now + (maxLifetimeSecs / 2);
  const idToken = '{' +
      '"iss":"testissuer",' +
      '"aud":"testaudience",' +
      '"azp":"testauthorisedparty",' +
      '"email_verified":"true",' +
      '"id":"123456789",' +
      '"sub":"123456789",' +
      '"email":"test@test.com",' +
      '"iat":' + now + ',' +
      '"exp":' + expiry + '}';
  const envelope = '{' +
      '"kid":"keyid",' +
      '"alg":"RS256"' +
      '}';

  let data = new Buffer(envelope).toString('base64') + '.' +
      new Buffer(idToken).toString('base64');

  const signer = crypto.createSign('sha256');
  signer.update(data);
  const signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.verifySignedJwtWithCerts(
      data, {keyid: publicKey}, 'testaudience', ['testissuer']);
  t.end();
});

test('should be able to retrieve a list of Google certificates', async t => {
  const scope =
      nock('https://www.googleapis.com')
          .get('/oauth2/v1/certs')
          .replyWithFile(
              200, path.join(__dirname, '../../test/fixtures/oauthcerts.json'));
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const {certs} = await client.getFederatedSignonCerts();
  t.assert(scope.isDone());
  t.equal(Object.keys(certs).length, 2);
  t.notEqual(certs['a15eea964ab9cce480e5ef4f47cb17b9fa7d0b21'], null);
  t.notEqual(certs['39596dc3a3f12aa74b481579e4ec944f86d24b95'], null);
  t.end();
});

test(
    'should be able to retrieve a list of Google certificates from cache again',
    async t => {
      const scope =
          nock('https://www.googleapis.com')
              .defaultReplyHeaders({
                'Cache-Control':
                    'public, max-age=23641, must-revalidate, no-transform',
                'Content-Type': 'application/json'
              })
              .get('/oauth2/v1/certs')
              .once()
              .replyWithFile(
                  200,
                  path.join(__dirname, '../../test/fixtures/oauthcerts.json'));
      const client = new OAuth2Client({clientId, clientSecret, redirectUri});
      const {certs} = await client.getFederatedSignonCerts();
      t.assert(scope.isDone());
      t.equal(Object.keys(certs).length, 2);
      const certs2 = (await client.getFederatedSignonCerts()).certs;
      t.equal(Object.keys(certs2).length, 2);
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
  t.plan(1);
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const generated = client.generateAuthUrl({client_id: 'client_override'});
  const parsed = url.parse(generated);
  if (typeof parsed.query !== 'string') {
    throw new Error('Unable to parse querystring');
  }
  const query = qs.parse(parsed.query);
  t.equal(query.client_id, 'client_override');
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
  const scope1 =
      nock('https://www.googleapis.com')
          .post('/oauth2/v4/token', undefined, {
            reqheaders: {'content-type': 'application/x-www-form-urlencoded'}
          })
          .reply(200, {access_token: 'abc123', expires_in: 1});

  const scope2 = nock('http://example.com').get('/').reply(200);
  return [scope1, scope2];
}

test('should refresh token if missing access token', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {refresh_token: 'refresh-token-placeholder'};
  const scopes = mockToken();
  await client.request({url: 'http://example.com'});
  scopes.forEach(s => t.assert(s.isDone()));
  t.equal('abc123', client.credentials.access_token);
  t.end();
});

test('should refresh if access token is expired', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'refresh-token-placeholder',
    expiry_date: (new Date()).getTime() - 1000
  };
  const scopes = mockToken();
  await client.request({url: 'http://example.com'});
  scopes.forEach(s => t.assert(s.isDone()));
  t.equal('abc123', client.credentials.access_token);
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
      const scopes = mockToken();
      await client.request({url: 'http://example.com'});
      scopes.forEach(s => t.assert(s.isDone()));
      t.equal('abc123', client.credentials.access_token);
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
      const scopes = mockToken();
      await client.request({url: 'http://example.com'});
      t.false(scopes[0].isDone());
      t.true(scopes[1].isDone());
      nock.cleanAll();
      t.equal('initial-access-token', client.credentials.access_token);
      t.end();
    });

test('should not refresh if not expired', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'refresh-token-placeholder',
    expiry_date: (new Date()).getTime() + 500000
  };
  const scopes = mockToken();
  await client.request({url: 'http://example.com'});
  t.false(scopes[0].isDone());
  t.true(scopes[1].isDone());
  nock.cleanAll();
  t.equal('initial-access-token', client.credentials.access_token);
  t.end();
});

test('should assume access token is not expired', async t => {
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'refresh-token-placeholder'
  };
  const scopes = mockToken();
  await client.request({url: 'http://example.com'});
  t.equal('initial-access-token', client.credentials.access_token);
  t.false(scopes[0].isDone());
  t.true(scopes[1].isDone());
  nock.cleanAll();
  t.end();
});

test('should revoke credentials if access token present', async t => {
  const scope = nock('https://accounts.google.com')
                    .get('/o/oauth2/revoke?token=abc')
                    .reply(200, {success: true});
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  client.credentials = {access_token: 'abc', refresh_token: 'abc'};
  const res = await client.revokeCredentials();
  t.assert(scope.isDone());
  t.equal(res.data!.success, true);
  t.equal(JSON.stringify(client.credentials), '{}');
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
  const scope =
      nock('https://www.googleapis.com')
          .post('/oauth2/v4/token', undefined, {
            reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'}
          })
          .reply(
              200, {access_token: 'abc', refresh_token: '123', expires_in: 10});
  const res =
      await client.getToken({code: 'code here', codeVerifier: 'its_verified'});
  t.assert(scope.isDone());
  const params = qs.parse(res.res.config.data);
  t.assert(params.code_verifier === 'its_verified');
  t.end();
});

test('should return expiry_date', async t => {
  const now = (new Date()).getTime();
  const scope =
      nock('https://www.googleapis.com')
          .post('/oauth2/v4/token', undefined, {
            reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'}
          })
          .reply(
              200, {access_token: 'abc', refresh_token: '123', expires_in: 10});
  const client = new OAuth2Client({clientId, clientSecret, redirectUri});
  const {tokens} = await client.getToken({code: 'code here'});
  t.assert(scope.isDone());
  t.true(tokens.expiry_date! >= now + (10 * 1000));
  t.true(tokens.expiry_date! <= now + (15 * 1000));
  t.end();
});
