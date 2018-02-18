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
    const pem = rsaPublicKeyPem(jwk.n, jwk.e);
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

export async function getSignature(data: string, privateKey: string) {
  if (isBrowser) {
    console.log(`GET SIGNATURE!\n---------------`);
    console.log(`data: ${data}`);
    console.log(`privateKey: ${privateKey}`);
    let key: CryptoKey;
    try {
      key = await window.crypto.subtle.importKey(
          'pkcs8', str2ab(privateKey), {name: algo, hash: {name: 'SHA-256'}},
          false, ['sign']);
    } catch (e) {
      console.error(JSON.stringify(e));
      throw e;
    }
    console.log(key);
    const signature = await window.crypto.subtle.sign(algo, key, str2ab(data));
    console.log(signature);
    return String.fromCharCode.apply(null, new Uint16Array(signature));
  } else {
    return crypto.createSign('RSA-SHA256')
        .update(data)
        .sign(privateKey, 'base64');
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

function rsaPublicKeyPem(modulusB64: string, exponentB64: string) {
  const modulus = new Buffer(modulusB64, 'base64');
  const exponent = new Buffer(exponentB64, 'base64');
  let modulusHex = modulus.toString('hex');
  let exponentHex = exponent.toString('hex');
  modulusHex = prepadSigned(modulusHex);
  exponentHex = prepadSigned(exponentHex);
  const modlen = modulusHex.length / 2;
  const explen = exponentHex.length / 2;
  const encodedModlen = encodeLengthHex(modlen);
  const encodedExplen = encodeLengthHex(explen);
  const encodedPubkey = '30' +
      encodeLengthHex(modlen + explen + encodedModlen.length / 2 +
                      encodedExplen.length / 2 + 2) +
      '02' + encodedModlen + modulusHex + '02' + encodedExplen + exponentHex;

  const derB64 = new Buffer(encodedPubkey, 'hex').toString('base64');

  const pem = '-----BEGIN RSA PUBLIC KEY-----\n' +
      derB64.match(/.{1,64}/g)!.join('\n') + '\n-----END RSA PUBLIC KEY-----\n';

  return pem;
}

function prepadSigned(hexStr: string) {
  const msb = hexStr[0];
  if (msb < '0' || msb > '7') {
    return '00' + hexStr;
  } else {
    return hexStr;
  }
}

function toHex(n: number) {
  const nstr = n.toString(16);
  if (nstr.length % 2) return '0' + nstr;
  return nstr;
}

// encode ASN.1 DER length field
// if <=127, short form
// if >=128, long form
function encodeLengthHex(n: number) {
  if (n <= 127) {
    return toHex(n);
  } else {
    const nHex = toHex(n);
    const lengthOfLengthByte = 128 + nHex.length / 2;  // 0x80+numbytes
    return toHex(lengthOfLengthByte) + nHex;
  }
}
