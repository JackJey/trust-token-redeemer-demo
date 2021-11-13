import cbor from "cbor";
import { webcrypto } from 'crypto';
import * as sfv from "structured-field-values";

// chrome canary M100
const headers = {
  connection: 'close',
  host: 'trust-token-redeemer-demo.glitch.me',
  'content-length': '0',
  pragma: 'no-cache',
  'cache-control': 'no-cache',
  'sec-ch-ua': '"Chromium";v="100", "Google Chrome";v="100", "(Not:A-Brand";v="99"',
  'sec-ch-ua-mobile': '?0',
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4700.0 Safari/537.36',
  'sec-ch-ua-platform': '"macOS"',
  accept: '*/*',
  origin: 'https://trust-token-redeemer-demo.glitch.me',
  'sec-fetch-site': 'same-origin',
  'sec-fetch-mode': 'cors',
  'sec-fetch-dest': 'empty',
  'sec-trust-tokens-additional-signing-data': 'additional_signing_data',
  'signed-headers': 'sec-redemption-record,sec-time,sec-trust-tokens-additional-signing-data',
  'sec-redemption-record': '"https://trust-token-issuer-demo.glitch.me";redemption-record=:eyJwdWJpY19tZXRhZGF0YSI6IDEsICJwcml2YXRlX21ldGFkYXRhIjogMH0=:',
  'sec-time': '2021-11-13T11:49:53.212Z',
  'sec-signature': 'signatures=("https://trust-token-issuer-demo.glitch.me";public-key=:BEq5ZCqPw45mme+Tjt7C1Xs9cPKGmaGADZMNmK2eTqT3FaNF+GibRIuFO48aRE1yfomTK7DOTPPnjTf8aPjo/gA=:;sig=:MEQCIAncKoQImFwKYplJ90DxOR+Yk3cu+aq5lw4W1ipSgSNlAiBjnFNIPdLoapbwOaL5/9OI/1xe4MHuQYrxJYFsnBy89w==:;alg="ecdsa_secp256r1_sha256"), sign-request-data=include',
  'sec-trust-token-version': 'TrustTokenV3',
  referer: 'https://trust-token-redeemer-demo.glitch.me/',
  'accept-encoding': 'gzip, deflate, br',
  'accept-language': 'en-US,en;q=0.9,ja;q=0.8',
  'x-forwarded-host': 'trust-token-redeemer-demo.glitch.me',
  traceparent: '00-13e292de42e147719024ed500a9aa594-4b217ad6776db57e-01'
}
console.log(headers)

const SecSignature = sfv.decodeDict(headers["sec-signature"])

const signature = SecSignature.signatures.value[0]
const sig = signature.params.sig
const client_public_key = signature.params["public-key"]

const destination = headers["host"]

const canonical_request_data = new Map([
  ["destination", destination],
  ["sec-redemption-record", headers["sec-redemption-record"]],
  ["sec-time", headers["sec-time"]],
  ["sec-trust-tokens-additional-signing-data", headers["sec-trust-tokens-additional-signing-data"]],
  ["public-key", client_public_key],
]);

console.log(canonical_request_data)

const cbor_data = cbor.encode(canonical_request_data);
const prefix = Buffer.from("TrustTokenV3");
const signing_data = new Uint8Array(Buffer.concat([prefix, cbor_data]));

const key = await webcrypto.subtle.importKey(
  "raw",
  client_public_key,
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  true,
  ["verify"]
);

console.log(key)

const result = await webcrypto.subtle.verify({
  name: "ECDSA",
  hash: "SHA-256",
}, key, sig, new Uint8Array(signing_data));

console.log(result)