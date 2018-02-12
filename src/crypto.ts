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

import * as buffer from 'buffer';
import * as crypto from 'crypto';

const isBrowser = (typeof window !== 'undefined');

export async function verifyPem(
    pubkey: string, data: string, signature: string,
    encoding: crypto.HexBase64Latin1Encoding) {
  if (isBrowser) {
    const key = await window.crypto.subtle.importKey(
        'raw', str2ab(data), {name: 'HMAC', hash: {name: 'SHA-256'}}, false,
        ['sign', 'verify']);
    return window.crypto.subtle.verify(
        'HMAC', key, str2ab(signature), str2ab(data));
  } else {
    return crypto.createVerify('sha256').update(data).verify(
        pubkey, signature, encoding);
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

export async function getSignature(data: string, privateKey: string) {
  if (isBrowser) {
    const key = await window.crypto.subtle.importKey(
        'raw', str2ab(data), {name: 'HMAC', hash: {name: 'SHA-256'}}, false,
        ['sign', 'verify']);
    const signature =
        await window.crypto.subtle.sign('HMAC', key, str2ab(data));
    return String.fromCharCode.apply(null, new Uint16Array(signature));
  } else {
    return crypto.createSign('sha256').update(data).sign(privateKey, 'base64');
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
