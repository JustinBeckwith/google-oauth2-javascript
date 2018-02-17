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

import {AxiosResponse} from 'axios';

export interface Credentials {
  refresh_token?: string;
  expiry_date?: number;
  access_token?: string;
  token_type?: string;
  id_token?: string;
}

export interface CredentialRequest {
  refresh_token?: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
}

export interface TokenPayload {
  /**
   * The Issuer Identifier for the Issuer of the response. Always
   * https://accounts.google.com or accounts.google.com for Google ID tokens.
   */
  iss: string;

  /**
   * Access token hash. Provides validation that the access token is tied to the
   * identity token. If the ID token is issued with an access token in the
   * server flow, this is always included. This can be used as an alternate
   * mechanism to protect against cross-site request forgery attacks, but if you
   * follow Step 1 and Step 3 it is not necessary to verify the access token.
   */
  at_hash?: string;

  /**
   * True if the user's e-mail address has been verified; otherwise false.
   */
  email_verified?: boolean;

  /**
   * An identifier for the user, unique among all Google accounts and never
   * reused. A Google account can have multiple emails at different points in
   * time, but the sub value is never changed. Use sub within your application
   * as the unique-identifier key for the user.
   */
  sub: string;

  /**
   * The client_id of the authorized presenter. This claim is only needed when
   * the party requesting the ID token is not the same as the audience of the ID
   * token. This may be the case at Google for hybrid apps where a web
   * application and Android app have a different client_id but share the same
   * project.
   */
  azp?: string;

  /**
   * The user's email address. This may not be unique and is not suitable for
   * use as a primary key. Provided only if your scope included the string
   * "email".
   */
  email?: string;

  /**
   * The URL of the user's profile page. Might be provided when:
   * - The request scope included the string "profile"
   * - The ID token is returned from a token refresh
   * - When profile claims are present, you can use them to update your app's
   * user records. Note that this claim is never guaranteed to be present.
   */
  profile?: string;

  /**
   * The URL of the user's profile picture. Might be provided when:
   * - The request scope included the string "profile"
   * - The ID token is returned from a token refresh
   * - When picture claims are present, you can use them to update your app's
   * user records. Note that this claim is never guaranteed to be present.
   */
  picture?: string;

  /**
   * The user's full name, in a displayable form. Might be provided when:
   * - The request scope included the string "profile"
   * - The ID token is returned from a token refresh
   * - When name claims are present, you can use them to update your app's user
   * records. Note that this claim is never guaranteed to be present.
   */
  name?: string;

  /**
   * The user's given name, in a displayable form. Might be provided when:
   * - The request scope included the string "profile"
   * - The ID token is returned from a token refresh
   * - When name claims are present, you can use them to update your app's user
   * records. Note that this claim is never guaranteed to be present.
   */
  given_name?: string;

  /**
   * The user's family name, in a displayable form. Might be provided when:
   * - The request scope included the string "profile"
   * - The ID token is returned from a token refresh
   * - When name claims are present, you can use them to update your app's user
   * records. Note that this claim is never guaranteed to be present.
   */
  family_name?: string;

  /**
   * Identifies the audience that this ID token is intended for. It must be one
   * of the OAuth 2.0 client IDs of your application.
   */
  aud: string;

  /**
   * The time the ID token was issued, represented in Unix time (integer
   * seconds).
   */
  iat: number;

  /**
   * The time the ID token expires, represented in Unix time (integer seconds).
   */
  exp: number;

  /**
   * The value of the nonce supplied by your app in the authentication request.
   * You should enforce protection against replay attacks by ensuring it is
   * presented only once.
   */
  nonce?: string;

  /**
   * The hosted G Suite domain of the user. Provided only if the user belongs to
   * a hosted domain.
   */
  hd?: string;
}

export interface GetTokenOptions {
  code: string;
  codeVerifier?: string;
}

export interface GenerateAuthUrlOpts {
  /**
   * Recommended. Indicates whether your application can refresh access tokens
   * when the user is not present at the browser. Valid parameter values are
   * 'online', which is the default value, and 'offline'. Set the value to
   * 'offline' if your application needs to refresh access tokens when the user
   * is not present at the browser. This value instructs the Google
   * authorization server to return a refresh token and an access token the
   * first time that your application exchanges an authorization code for
   * tokens.
   */
  access_type?: string;

  /**
   * The 'response_type' will always be set to 'CODE'.
   */
  response_type?: string;

  /**
   * The client ID for your application. The value passed into the constructor
   * will be used if not provided. You can find this value in the API Console.
   */
  client_id?: string;

  /**
   * Determines where the API server redirects the user after the user
   * completes the authorization flow. The value must exactly match one of the
   * 'redirect_uri' values listed for your project in the API Console. Note that
   * the http or https scheme, case, and trailing slash ('/') must all match.
   * The value passed into the constructor will be used if not provided.
   */
  redirect_uri?: string;

  /**
   * Required. A space-delimited list of scopes that identify the resources that
   * your application could access on the user's behalf. These values inform the
   * consent screen that Google displays to the user. Scopes enable your
   * application to only request access to the resources that it needs while
   * also enabling users to control the amount of access that they grant to your
   * application. Thus, there is an inverse relationship between the number of
   * scopes requested and the likelihood of obtaining user consent. The
   * OAuth 2.0 API Scopes document provides a full list of scopes that you might
   * use to access Google APIs. We recommend that your application request
   * access to authorization scopes in context whenever possible. By requesting
   * access to user data in context, via incremental authorization, you help
   * users to more easily understand why your application needs the access it is
   * requesting.
   */
  scope?: string[]|string;

  /**
   * Recommended. Specifies any string value that your application uses to
   * maintain state between your authorization request and the authorization
   * server's response. The server returns the exact value that you send as a
   * name=value pair in the hash (#) fragment of the 'redirect_uri' after the
   * user consents to or denies your application's access request. You can use
   * this parameter for several purposes, such as directing the user to the
   * correct resource in your application, sending nonces, and mitigating
   * cross-site request forgery. Since your redirect_uri can be guessed, using a
   * state value can increase your assurance that an incoming connection is the
   * result of an authentication request. If you generate a random string or
   * encode the hash of a cookie or another value that captures the client's
   * state, you can validate the response to additionally ensure that the
   * request and response originated in the same browser, providing protection
   * against attacks such as cross-site request forgery. See the OpenID Connect
   * documentation for an example of how to create and confirm a state token.
   */
  state?: string;

  /**
   * Optional. Enables applications to use incremental authorization to request
   * access to additional scopes in context. If you set this parameter's value
   * to true and the authorization request is granted, then the new access token
   * will also cover any scopes to which the user previously granted the
   * application access. See the incremental authorization section for examples.
   */
  include_granted_scopes?: boolean;

  /**
   * Optional. If your application knows which user is trying to authenticate,
   * it can use this parameter to provide a hint to the Google Authentication
   * Server. The server uses the hint to simplify the login flow either by
   * prefilling the email field in the sign-in form or by selecting the
   * appropriate multi-login session. Set the parameter value to an email
   * address or sub identifier, which is equivalent to the user's Google ID.
   */
  login_hint?: string;

  /**
   * Optional. A space-delimited, case-sensitive list of prompts to present the
   * user. If you don't specify this parameter, the user will be prompted only
   * the first time your app requests access.  Possible values are:
   *
   * 'none' - Donot display any authentication or consent screens. Must not be
   *        specified with other values.
   * 'consent' - 	Prompt the user for consent.
   * 'select_account' - Prompt the user to select an account.
   */
  prompt?: string;

  /**
   * Recommended. Specifies what method was used to encode a 'code_verifier'
   * that will be used during authorization code exchange. This parameter must
   * be used with the 'code_challenge' parameter. The value of the
   * 'code_challenge_method' defaults to "plain" if not present in the request
   * that includes a 'code_challenge'. The only supported values for this
   * parameter are "S256" or "plain".
   */
  code_challenge_method?: CodeChallengeMethod;

  /**
   * Recommended. Specifies an encoded 'code_verifier' that will be used as a
   * server-side challenge during authorization code exchange. This parameter
   * must be used with the 'code_challenge' parameter described above.
   */
  code_challenge?: string;
}

export interface GetTokenResponse {
  tokens: Credentials;
  res: AxiosResponse;
}

export interface RevokeCredentialsResult { success: boolean; }

export interface VerifyIdTokenOptions {
  idToken: string;
  audience: string|string[];
  maxExpiry?: number;
}

export interface Options {
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  eagerRefreshThresholdMillis?: number;
}

export type HttpHeaders = {
  [index: string]: string|undefined
};

export enum CodeChallengeMethod {
  Plain = 'plain',
  S256 = 'S256'
}

export interface Certs { [index: string]: string; }

export interface JWTHeader {
  alg: string;
  typ: string;
}
