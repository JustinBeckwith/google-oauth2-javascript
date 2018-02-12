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

import axios, {AxiosError, AxiosPromise, AxiosRequestConfig, AxiosResponse} from 'axios';
import * as qs from 'querystring';

import * as crypto from './crypto';
import * as i from './interfaces';
import {LoginTicket} from './loginticket';

export class OAuth2Client {
  private certificateCache: i.Certs = {};
  private certificateExpiry?: Date;
  protected readonly options: i.Options;
  credentials: i.Credentials = {};

  /**
   * Handles OAuth2 flow for Google APIs.
   */
  constructor(options: i.Options) {
    this.options = options;
  }

  private readonly AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
  private readonly TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token';
  private readonly REVOKE_URL = 'https://accounts.google.com/o/oauth2/revoke';
  private readonly FEDERATED_SIGNON_CERTS_URL =
      'https://www.googleapis.com/oauth2/v1/certs';

  /**
   * Clock skew - five minutes in seconds
   */
  private static readonly CLOCK_SKEW_SECS_ = 300;

  /**
   * Max Token Lifetime is one day in seconds
   */
  private static readonly MAX_TOKEN_LIFETIME_SECS_ = 86400;

  /**
   * The allowed oauth token issuers.
   */
  private static readonly ISSUERS_ =
      ['accounts.google.com', 'https://accounts.google.com'];

  /**
   * Generates URL for consent page landing.
   * @param opts Options.
   * @return URL to consent page.
   */
  generateAuthUrl(opts: i.GenerateAuthUrlOpts = {}) {
    if (opts.code_challenge_method && !opts.code_challenge) {
      throw new Error(
          'If a code_challenge_method is provided, code_challenge must be included.');
    }
    opts.response_type = opts.response_type || 'code';
    opts.client_id = opts.client_id || this.options.clientId;
    opts.redirect_uri = opts.redirect_uri || this.options.redirectUri;
    if (opts.scope instanceof Array) {
      opts.scope = opts.scope.join(' ');
    }
    return this.AUTH_URL + '?' + qs.stringify(opts);
  }

  /**
   * Convenience method to automatically generate a code_verifier, and it's
   * resulting SHA256. If used, this must be paired with a S256
   * code_challenge_method.
   */
  async generateCodeVerifier() {
    // base64 encoding uses 6 bits per character, and we want to generate 128
    // characters. 6*128/8 = 96.
    const randomString = crypto.randomString(96);
    // The valid characters in the code_verifier are [A-Z]/[a-z]/[0-9]/
    // "-"/"."/"_"/"~". Base64 encoded strings are pretty close, so we're just
    // swapping out a few chars.
    const codeVerifier =
        randomString.replace(/\+/g, '~').replace(/=/g, '_').replace(/\//g, '-');
    // Generate the base64 encoded SHA256
    const unencodedCodeChallenge = await crypto.hashIt(codeVerifier);
    // We need to use base64UrlEncoding instead of standard base64
    const codeChallenge = unencodedCodeChallenge.split('=')[0]
                              .replace(/\+/g, '-')
                              .replace(/\//g, '_');
    return {codeVerifier, codeChallenge};
  }

  /**
   * Gets the access token for the given code.
   */
  async getToken(options: i.GetTokenOptions) {
    const values = {
      code: options.code,
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
      redirect_uri: this.options.redirectUri,
      grant_type: 'authorization_code',
      code_verifier: options.codeVerifier
    };
    const res = await axios.post<i.CredentialRequest>(
        this.TOKEN_URL, qs.stringify(values),
        {headers: {'Content-Type': 'application/x-www-form-urlencoded'}});
    const tokens = res.data as i.Credentials;
    if (res.data && res.data.expires_in) {
      tokens.expiry_date =
          ((new Date()).getTime() + (res.data.expires_in * 1000));
      delete (tokens as i.CredentialRequest).expires_in;
    }
    this.credentials = tokens;
    return {tokens, res};
  }

  /**
   * Refreshes the access token.
   * @param refreshToken Existing refresh token.
   */
  async refreshAccessToken(refreshToken?: string) {
    refreshToken = refreshToken || this.credentials.refresh_token;
    if (!refreshToken) {
      throw new Error('No refresh token available.');
    }
    const data = {
      refresh_token: refreshToken,
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
      grant_type: 'refresh_token'
    };
    const res = await axios.post<i.CredentialRequest>(
        this.TOKEN_URL, qs.stringify(data),
        {headers: {'Content-Type': 'application/x-www-form-urlencoded'}});
    const tokens = res.data as i.Credentials;
    if (res.data && res.data.expires_in) {
      tokens.expiry_date =
          ((new Date()).getTime() + (res.data.expires_in * 1000));
      delete (tokens as i.CredentialRequest).expires_in;
    }
    return {tokens, res};
  }

  /**
   * Obtain an access token.  Refresh if needed.
   */
  async getAccessToken() {
    const shouldRefresh =
        !this.credentials.access_token || this.isTokenExpiring();
    if (shouldRefresh && this.credentials.refresh_token) {
      if (!this.credentials.refresh_token) {
        throw new Error('No refresh token is set.');
      }
      const r = await this.refreshAccessToken(this.credentials.refresh_token);
      const tokens = r.tokens as i.Credentials;
      tokens.refresh_token = this.credentials.refresh_token;
      this.credentials = tokens;
      if (!this.credentials ||
          (this.credentials && !this.credentials.access_token)) {
        throw new Error('Could not refresh access token.');
      }
      return {token: this.credentials.access_token, res: r.res};
    } else {
      return {token: this.credentials.access_token};
    }
  }

  /**
   * Obtain a set of headers which can be attached to a request.
   * @param url The url for which this request will be made.
   */
  async getRequestMetadata(url: string) {
    const thisCreds = this.credentials;

    // make sure we have an access token or a refresh token
    if (!thisCreds.access_token && !thisCreds.refresh_token) {
      throw new Error('No access, or refresh token is set.');
    }

    // if we have the access token, just return it
    if (thisCreds.access_token && !this.isTokenExpiring()) {
      thisCreds.token_type = thisCreds.token_type || 'Bearer';
      const headers = {
        Authorization: thisCreds.token_type + ' ' + thisCreds.access_token
      };
      return {headers};
    }

    // We need an access token.  Lets try to get one!
    const r = await this.refreshAccessToken(thisCreds.refresh_token);

    // Save the refresh token for future use.
    r.tokens.refresh_token = thisCreds.refresh_token;
    this.credentials = r.tokens;

    const tokenType = thisCreds.token_type || 'Bearer';
    const headers = {Authorization: `${tokenType}  ${r.tokens.access_token}`};
    return {headers, res: r.res};
  }

  /**
   * Revokes the access given to token.
   * @param token The existing token to be revoked.
   */
  async revokeToken(token: string) {
    return axios.request<i.RevokeCredentialsResult>(
        {url: this.REVOKE_URL, params: {token}});
  }

  /**
   * Revokes access token and clears the credentials object
   */
  async revokeCredentials() {
    const token = this.credentials.access_token;
    this.credentials = {};
    if (!token) {
      throw new Error('No access token to revoke.');
    }
    return this.revokeToken(token);
  }

  /**
   * Provides a request implementation with OAuth 2.0 flow. If credentials have
   * a refresh_token, in cases of HTTP 401 and 403 responses, it automatically
   * asks for a new access token and replays the unsuccessful request.
   * @param opts Request options.
   * @return Request object
   */
  async request<T>(url: string): Promise<AxiosResponse<T>>;
  async request<T>(opts: AxiosRequestConfig): Promise<AxiosResponse<T>>;
  async request<T>(optsOrUrl: AxiosRequestConfig|
                   string): Promise<AxiosResponse<T>> {
    const opts = (typeof optsOrUrl === 'string') ? {url: optsOrUrl} : optsOrUrl;
    const r = await this.getRequestMetadata(opts.url!);
    if (r.headers && r.headers.Authorization) {
      opts.headers = opts.headers || {};
      opts.headers.Authorization = r.headers.Authorization;
    }
    return axios.request<T>(opts);
  }

  /**
   * Verify id token is token by checking the certs and audience
   * @param options that contains all options.
   */
  async verifyIdToken(options: i.VerifyIdTokenOptions) {
    if (typeof options !== 'object' || !options.idToken) {
      throw new Error(
          'This method accepts an options object as the first parameter, which includes the idToken, audience, and maxExpiry.');
    }
    const response = await this.getFederatedSignonCerts();
    const login = await this.verifySignedJwtWithCerts(
        options.idToken, response.certs, options.audience,
        OAuth2Client.ISSUERS_, options.maxExpiry);
    return login;
  }

  /**
   * Gets federated sign-on certificates to use for verifying identity tokens.
   * Returns certs as array structure, where keys are key ids, and values
   * are PEM encoded certificates.
   */
  async getFederatedSignonCerts() {
    const nowTime = (new Date()).getTime();
    if (this.certificateExpiry &&
        (nowTime < this.certificateExpiry.getTime())) {
      return {certs: this.certificateCache};
    }
    const res = await axios.get<i.Certs>(this.FEDERATED_SIGNON_CERTS_URL);
    const cacheControl = res ? res.headers['cache-control'] : undefined;
    let cacheAge = -1;
    if (cacheControl) {
      const pattern = new RegExp('max-age=([0-9]*)');
      const regexResult = pattern.exec(cacheControl as string);
      if (regexResult && regexResult.length === 2) {
        // Cache results with max-age (in seconds)
        cacheAge = Number(regexResult[1]) * 1000;  // milliseconds
      }
    }
    const now = new Date();
    this.certificateExpiry =
        cacheAge === -1 ? undefined : new Date(now.getTime() + cacheAge);
    this.certificateCache = res.data;
    return {certs: res.data, res};
  }

  /**
   * Verify the id token is signed with the correct certificate
   * and is from the correct audience.
   * @param jwt The jwt to verify (The ID Token in this case).
   * @param certs The array of certs to test the jwt against.
   * @param requiredAudience The audience to test the jwt against.
   * @param issuers The allowed issuers of the jwt (Optional).
   * @param maxExpiry The max expiry the certificate can be (Optional).
   * @return Returns a LoginTicket on verification.
   */
  async verifySignedJwtWithCerts(
      jwt: string, certs: {}, requiredAudience: string|string[],
      issuers?: string[], maxExpiry?: number) {
    if (!maxExpiry) {
      maxExpiry = OAuth2Client.MAX_TOKEN_LIFETIME_SECS_;
    }

    const segments = jwt.split('.');
    if (segments.length !== 3) {
      throw new Error('Wrong number of segments in token: ' + jwt);
    }
    const signed = segments[0] + '.' + segments[1];
    const signature = segments[2];

    let envelope;
    let payload: i.TokenPayload;

    try {
      envelope = JSON.parse(this.decodeBase64(segments[0]));
    } catch (err) {
      throw new Error('Can\'t parse token envelope: ' + segments[0]);
    }

    if (!envelope) {
      throw new Error('Can\'t parse token envelope: ' + segments[0]);
    }

    try {
      payload = JSON.parse(this.decodeBase64(segments[1]));
    } catch (err) {
      throw new Error('Can\'t parse token payload: ' + segments[0]);
    }

    if (!payload) {
      throw new Error('Can\'t parse token payload: ' + segments[1]);
    }

    if (!certs.hasOwnProperty(envelope.kid)) {
      // If this is not present, then there's no reason to attempt verification
      throw new Error('No pem found for envelope: ' + JSON.stringify(envelope));
    }
    // certs is a legit dynamic object
    // tslint:disable-next-line no-any
    const pem = (certs as any)[envelope.kid];
    const verified = await crypto.verifyPem(pem, signed, signature, 'base64');

    if (!verified) {
      throw new Error('Invalid token signature: ' + jwt);
    }

    if (!payload.iat) {
      throw new Error('No issue time in token: ' + JSON.stringify(payload));
    }

    if (!payload.exp) {
      throw new Error(
          'No expiration time in token: ' + JSON.stringify(payload));
    }

    const iat = Number(payload.iat);
    if (isNaN(iat)) throw new Error('iat field using invalid format');

    const exp = Number(payload.exp);
    if (isNaN(exp)) throw new Error('exp field using invalid format');

    const now = new Date().getTime() / 1000;

    if (exp >= now + maxExpiry) {
      throw new Error(
          'Expiration time too far in future: ' + JSON.stringify(payload));
    }

    const earliest = iat - OAuth2Client.CLOCK_SKEW_SECS_;
    const latest = exp + OAuth2Client.CLOCK_SKEW_SECS_;

    if (now < earliest) {
      throw new Error(
          'Token used too early, ' + now + ' < ' + earliest + ': ' +
          JSON.stringify(payload));
    }

    if (now > latest) {
      throw new Error(
          'Token used too late, ' + now + ' > ' + latest + ': ' +
          JSON.stringify(payload));
    }

    if (issuers && issuers.indexOf(payload.iss) < 0) {
      throw new Error(
          'Invalid issuer, expected one of [' + issuers + '], but got ' +
          payload.iss);
    }

    // Check the audience matches if we have one
    if (typeof requiredAudience !== 'undefined' && requiredAudience !== null) {
      const aud = payload.aud;
      let audVerified = false;
      // If the requiredAudience is an array, check if it contains token
      // audience
      if (requiredAudience.constructor === Array) {
        audVerified = (requiredAudience.indexOf(aud) > -1);
      } else {
        audVerified = (aud === requiredAudience);
      }
      if (!audVerified) {
        throw new Error(
            'Wrong recipient, payload audience != requiredAudience');
      }
    }
    return new LoginTicket(envelope, payload);
  }

  /**
   * This is a utils method to decode a base64 string
   * @param b64String The string to base64 decode
   * @return The decoded string
   */
  protected decodeBase64(b64String: string) {
    const buffer = new Buffer(b64String, 'base64');
    return buffer.toString('utf8');
  }

  /**
   * Returns true if a token is expired or will expire within
   * eagerRefreshThresholdMillismilliseconds.
   * If there is no expiry time, assumes the token is not expired or expiring.
   */
  protected isTokenExpiring(): boolean {
    const expiryDate = this.credentials.expiry_date;
    const threshold = this.options.eagerRefreshThresholdMillis || 5 * 60 * 1000;
    return expiryDate ? expiryDate <= ((new Date()).getTime() + threshold) :
                        false;
  }
}
