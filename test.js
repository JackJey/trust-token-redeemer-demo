import cbor from "cbor";
const {
  webcrypto
} = await import('crypto');

const { b64 } = {
  b64: 'o2NzaWfYQFhHMEUCIQDgoSZcEIPpOF6CMeFkVyj7qMwjIya0+4VpcYj0V/lQLAIgOLL+8tjaKG9tITYUC37nYT696nYs3XzWM/Z02756ogtsc2lnbmluZ19kYXRhWQGHVHJ1c3RUb2tlblYzpWhzZWMtdGltZXgYMjAyMS0xMS0xMlQxNjozMDo0Mi44MTdaanB1YmxpYy1rZXnYQFhBBEq5ZCqPw45mme+Tjt7C1Xs9cPKGmaGADZMNmK2eTqT3FaNF+GibRIuFO48aRE1yfomTK7DOTPPnjTf8aPjo/gBrZGVzdGluYXRpb254I3RydXN0LXRva2VuLXJlZGVlbWVyLWRlbW8uZ2xpdGNoLm1ldXNlYy1yZWRlbXB0aW9uLXJlY29yZHh8Imh0dHBzOi8vdHJ1c3QtdG9rZW4taXNzdWVyLWRlbW8uZ2xpdGNoLm1lIjtyZWRlbXB0aW9uLXJlY29yZD06ZXlKd2RXSnBZMTl0WlhSaFpHRjBZU0k2SURFc0lDSndjbWwyWVhSbFgyMWxkR0ZrWVhSaElqb2dNSDA9Ongoc2VjLXRydXN0LXRva2Vucy1hZGRpdGlvbmFsLXNpZ25pbmctZGF0YXdhZGRpdGlvbmFsX3NpZ25pbmdfZGF0YXFjbGllbnRfcHVibGljX2tledhAWEEESrlkKo/DjmaZ75OO3sLVez1w8oaZoYANkw2YrZ5OpPcVo0X4aJtEi4U7jxpETXJ+iZMrsM5M8+eNN/xo+Oj+AA=='
}

// ecdsa_secp256r1_sha256
const { sig, signing_data, client_public_key } = cbor.decode(Buffer.from(b64, 'base64'))
console.log({
  sig,
  signing_data,
  client_public_key
})

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