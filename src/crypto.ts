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
  if (isBrowser) {
    console.log('VERIFY JWK!!!\n--------------');
    console.log(`jwk: ${jwk}`);
    console.log(`data: ${data}`);
    console.log(`signature: ${signature}`);
    const key = await window.crypto.subtle.importKey(
        'jwk', jwk, {name: 'RSASSA-PKCS1-v1_5', hash: {name: 'SHA-256'}}, false,
        ['verify']);
    console.log(key);
    return window.crypto.subtle.verify(
        algo, key, str2ab(signature), str2ab(data));
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
    const notb = window.crypto.getRandomValues(array);
    const rando = String.fromCharCode.apply(null, notb);
    const b64Rando = btoa(rando);
    return b64Rando;
  } else {
    return crypto.randomBytes(size).toString('base64');
  }
}

export async function hashIt(data: string) {
  if (isBrowser) {
    const buf = Buffer.from(data, 'utf-8');
    const hashBuf = await window.crypto.subtle.digest('SHA-256', buf);
    const hash = Buffer.from(hashBuf).toString('base64');
    return hash;
  } else {
    return crypto.createHash('sha256').update(data).digest('base64');
  }
}

export async function getSignature(data: string, jwk: JWK) {
  if (isBrowser) {
    console.log(`GET SIGNATURE!\n---------------`);
    console.log(`data: ${data}`);
    console.log(`privateKey: ${jwk}`);
    const key = await window.crypto.subtle.importKey(
        'jwk', jwk, {name: algo, hash: {name: 'SHA-256'}}, false, ['sign']);
    console.log(`key: ${key}`);
    const signature = await window.crypto.subtle.sign(algo, key, str2ab(data));
    console.log(signature);
    return String.fromCharCode.apply(null, new Uint16Array(signature));
  } else {
    const pem = p2j.jwk2pem(jwk);
    console.log(pem);
    const sig = crypto.createSign('sha256').update(data).sign(pem, 'base64');
    console.log(`sig: ${sig}`);
    return sig;
  }
}

function str2ab(str: string) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
