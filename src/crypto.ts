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
import {JWK} from './interfaces';
const p2j = require('pem-jwk');

const isBrowser = (typeof window !== 'undefined');
const algo = 'RSASSA-PKCS1-v1_5';

export async function verify(jwk: JWK, data: string, signature: string) {
  console.log('VERIFY JWK!!!\n--------------');
  console.log(`jwk: ${JSON.stringify(jwk)}`);
  console.log(`data: ${data}`);
  console.log(`signature: ${signature}`);
  if (isBrowser) {
    const key = await window.crypto.subtle.importKey(
        'jwk', jwk, {name: algo, hash: {name: 'SHA-256'}}, false, ['verify']);
    return window.crypto.subtle.verify(
        algo, key, Buffer.from(signature), Buffer.from(data));
  } else {
    const pem = p2j.jwk2pem(jwk);
    return crypto.createVerify('RSA-SHA256')
        .update(data)
        .verify(pem, signature, 'base64');
  }
}

export function randomString(size: number) {
  if (isBrowser) {
    const array = new Uint8Array(size);
    window.crypto.getRandomValues(array);
    const rando = Buffer.from(array.buffer).toString('base64');
    return rando;
  } else {
    return crypto.randomBytes(size).toString('base64');
  }
}

export async function hashIt(data: string) {
  if (isBrowser) {
    const buf = Buffer.from(data);
    const hashBuf = await window.crypto.subtle.digest('SHA-256', buf);
    const hash = Buffer.from(hashBuf).toString('base64');
    return hash;
  } else {
    return crypto.createHash('sha256').update(data).digest('base64');
  }
}

export async function getSignature(data: string, jwk: JWK) {
  console.log(`GET SIGNATURE!\n---------------`);
  console.log(`data: ${data}`);
  console.log(`privateKey: ${JSON.stringify(jwk)}`);
  if (isBrowser) {
    const key = await window.crypto.subtle.importKey(
        'jwk', jwk, {name: algo, hash: {name: 'SHA-256'}}, false, ['sign']);
    const signature =
        await window.crypto.subtle.sign(algo, key, Buffer.from(data));
    const sig = Buffer.from(signature).toString('base64');
    console.log(`sig: ${sig}`);
    return sig;
  } else {
    const pem = p2j.jwk2pem(jwk);
    console.log(pem);
    const sig = crypto.createSign('sha256').update(data).sign(pem, 'base64');
    console.log(`sig: ${sig}`);
    return sig;
  }
}
