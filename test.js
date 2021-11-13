import cbor from "cbor";
import { webcrypto } from 'crypto';
import * as sfv from "structured-field-values";


const headers = {
  "sec-redemption-record": `"https://a.test:39135";redemption-record=:Ym9keT06cEdodFpYUmhaR0YwWWFKbWNIVmliR2xqQUdkd2NtbDJZWFJsQUdwMGIydGxiaTFvWVhOb1dDQXlSWnJWdUhJYzBYYjlPRzNxZFZLcmdoYncxeUlnSklLTGtGQjl4Qllob1d0amJHbGxiblF0WkdGMFlhTm9hMlY1TFdoaGMyaFlJRzdoV1FmSG5lVS9YcjVyVlRJeTlWeXN1MGorY203dWl0UkdSUXpnMW5SYmNISmxaR1ZsYldsdVp5MXZjbWxuYVc1MGFIUjBjSE02THk5aExuUmxjM1E2TXpreE16VjBjbVZrWlcxd2RHbHZiaTEwYVcxbGMzUmhiWEFhWVA5RVJuQmxlSEJwY25rdGRHbHRaWE4wWVcxd0FBPT06LCBzaWduYXR1cmU9OktWR0tzWnoyVXV1bzhCZ0hnSmtyVmRmdTg5R2J0V1VIME1HVG1tQWJWSWtHdWRqMXVKbTVVbVFHQS83Y09LenB2V1E4L2M1REdBNEFqQW9SQnJ1TENRPT06:`,
  "sec-signature": `signatures=("https://a.test:39135";public-key=:BCGEjkKZJuBqMIcpOkPh7pUYLSHUfVHJHTET/aBfsCY6GOAEY2lEILA1HTPFl7Sk4Mbr6BLbMOx9i/SXEXb08dE=:;sig=:MEUCIBMpY10dGkgFwEYtBydjHIKuqcUwFJpGXArQ+Lbssii5AiEA9twtv8vXAPQoCc/9BVBQSI6SOvN/yBmKFq58X7HOsaY=:;alg="ecdsa_secp256r1_sha256"), sign-request-data=include`,
  "sec-trust-token-version": `TrustTokenV3`
}

// console.log(header)

const SecRedumptionRecord = sfv.decodeList(headers["sec-redemption-record"])[0]
const SecSignature = sfv.decodeDict(headers["sec-signature"])

console.log({ SecRedumptionRecord })
console.log({ SecSignature })

const signature = SecSignature.signatures.value[0]

const sig = signature.params.sig
const client_public_key = signature.params['public-key']
console.log(sig)
console.log(client_public_key)

const destination = "a.test"

// verify sec-signature
const canonical_request_data = new Map([
  ["destination", destination],
  ["sec-redemption-record", headers["sec-redemption-record"]],
  // ["sec-time", headers["sec-time"]],
  // ["sec-trust-tokens-additional-signing-data", headers["sec-trust-tokens-additional-signing-data"]],
  ["public-key", client_public_key],
]);

console.log(canonical_request_data)

const cbor_data = cbor.encode(canonical_request_data);
const prefix = Buffer.from("TrustTokenV3");
console.log({ prefix })
const signing_data = new Uint8Array(Buffer.concat([prefix, cbor_data]));

const key = await webcrypto.subtle.importKey(
  'raw',
  client_public_key,
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  true,
  ['verify']
);

console.log(key)

const result = await webcrypto.subtle.verify({
  name: "ECDSA",
  hash: "SHA-256",
}, key, sig, new Uint8Array(signing_data));

console.log(result)