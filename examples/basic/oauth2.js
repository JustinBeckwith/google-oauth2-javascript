// Copyright 2018, Google, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

const { OAuth2Client } = require('@google/oauth2');
const http = require('http');
const url = require('url');
const querystring = require('querystring');
const opn = require('opn');
const destroyer = require('server-destroy');

// Download your OAuth2 configuration from the Google
const keys = require('./../keys.json');

async function main() {
  // Start by acquiring a pre-authenticated oAuth2 client.
  const oAuth2Client = await getClient();

  /**
   * The access_token you get back from the `getToken` method will eventually
   * expire. You can find the expiration date by looking at `expiry_date`.
   * When you ask for an access_token the first time, you also get a
   * refresh_token back with the response. This refresh_token is a magic
   * key that lets you keep asking for new access_token(s). That means you
   * need to treat it with care!  This library will automatically hang onto
   * the refresh_token when we get it, and use that to automatically ask for
   * new access_token(s) before the current one expires (we're nice like that).
   * You can also store (securely!) the refresh_token for a given user if you
   * want to let them start another session later.
   */
  console.log(`Access Token: ${oAuth2Client.credentials.access_token}`);
  console.log(`Access Token Expiration: ${oAuth2Client.credentials.expiry_date}`);
  console.log(`Refresh Token: ${oAuth2Client.credentials.refresh_token}`);

  /**
   * The good news is that you don't need to understand all of that to use this
   * library. This example shows making a simple request to the Google Plus API
   * using our pre-authenticated client. The `request()` method
   * takes an AxiosRequestConfig object, which can be customized.
   * Visit https://github.com/axios/axios#request-config to learn more.
   */
  const url = 'https://www.googleapis.com/plus/v1/people?query=pizza';
  const res = await oAuth2Client.request({ url });
  console.log(res.data);
}

/**
 * Create a new OAuth2Client, and go through the OAuth2 content
 * workflow.  Return the full client to the callback.
 */
function getClient() {
  return new Promise((resolve, reject) => {
    // create an oAuth client to authorize the API call.  Secrets are kept in a `keys.json` file,
    // which should be downloaded from the Google Developers Console.
    const oAuth2Client = new OAuth2Client({
      clientId: keys.web.client_id,
      clientSecret: keys.web.client_secret,
      redirectUri: keys.web.redirect_uris[0]
    });

    // Generate a code_verifier and code_challenge
    const codes = oAuth2Client.generateCodeVerifier();
    console.log(codes);

    // Generate the url that will be used for the consent dialog.
    const authorizeUrl = oAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: 'https://www.googleapis.com/auth/plus.me',
      // When using `generateCodeVerifier`, make sure to use code_challenge_method 'S256'.
      code_challenge_method: 'S256',
      // Pass along the generated code challenge.
      code_challenge: codes.codeChallenge
    });

    // Open an http server to accept the oauth callback. In this simple example, the
    // only request to our webserver is to /oauth2callback?code=<code>
    let browserProcess;
    const server = http
      .createServer(async (req, res) => {
        if (req.url.indexOf('/oauth2callback') > -1) {
          // acquire the code from the querystring, and close the web server.
          const qs = querystring.parse(url.parse(req.url).query);
          console.log(`Code is ${qs.code}`);
          res.end('Authentication successful! Please return to the console.');
          server.destroy();

          // Now that we have the code, use that to acquire tokens.
          try {
            const r = await oAuth2Client.getToken({ code: qs.code, codeVerifier: codes.codeVerifier });
            console.info('Tokens acquired.');
            resolve(oAuth2Client);
          } catch (e) {
            console.error(e);
          }
        }
      })
      .listen(3000, async () => {
        // open the browser to the authorize url to start the workflow
        (await opn(authorizeUrl, {wait: false})).unref();
      });
      destroyer(server);
  });
}

main().catch(console.error);
