const express = require("express");
const app = express();
const cbor = require("cbor");
const sfv = require("structured-field-values");
const ed25519 = require("noble-ed25519");
const crypto = require("crypto");
const fs = require("fs");
const fetch = require("node-fetch");

const { trust_token } = require("./package.json");

app.use(express.static("public"));

app.get("/", async (request, response) => {
  response.sendFile(__dirname + "/views/index.html");
});

app.post(`/.well-known/trust-token/send-srr`, async (req, res) => {
  console.log(req.path);

  const headers = req.headers;

  // sec-signed-redemption-record
  // [(<issuer 1>, {"redemption-record": <SRR 1>}),
  //  (<issuer N>, {"redemption-record": <SRR N>})],
  const srr = sfv.parseList(headers["sec-signed-redemption-record"]);
  const redemption_record = sfv.parseDict(
    Buffer.from(srr[0]["params"]["redemption-record"]).toString()
  );

  const { body, signature } = redemption_record;

  const key_commitment_url =
    "https://trust-token-issuer.glitch.me/.well-known/trust-token/key-commitment";
  const key_commitment_res = await fetch(key_commitment_url);
  const key_commitment = await key_commitment_res.json();

  // verify signature
  const srr_public_key = Buffer.from(
    key_commitment.COMMITMENT["https://trust-token-issuer.glitch.me"].srrkey,
    "base64"
  );
  const srr_verify = await ed25519.verify(
    signature.value,
    body.value,
    srr_public_key
  );
  console.log({ srr_verify });

  // parse SRR
  const srr_body = cbor.decodeAllSync(Buffer.from(body.value))[0];
  const metadata = srr_body["metadata"];
  const token_hash = srr_body["token-hash"];
  const client_data = srr_body["client-data"];
  const key_hash = client_data["key-hash"];
  const redeeming_origin = client_data["redeeming_origin"];
  const redeeming_timestamp = client_data["redeeming_timestamp"];
  const expiry_timestamp = srr_body["expiry-timestamp"];

  // verify client_public_key
  const sec_signature = sfv.parseDict(headers["sec-signature"]);
  const client_public_key =
    sec_signature.signatures.value[0].params["public-key"];
  const sig = sec_signature.signatures.value[0].params["sig"];

  const client_public_key_hash = crypto
    .createHash("sha256")
    .update(client_public_key)
    .digest();
  const public_key_verify =
    client_public_key_hash.toString() === key_hash.toString();
  console.log({ public_key_verify });

  // verify sec-signature
  const canonical_request_data = cbor.encode(
    new Map([
      ["sec-time", headers["sec-time"]],
      ["public-key", client_public_key],
      ["destination", "trust-token-redeemer.glitch.me"],
      ["sec-signed-redemption-record", headers["sec-signed-redemption-record"]],
      [
        "sec-trust-tokens-additional-signing-data",
        headers["sec-trust-tokens-additional-signing-data"]
      ]
    ])
  );

  const prefix = Buffer.from("Trust Token v0");
  const signing_data = Buffer.concat([prefix, canonical_request_data]);
  const sig_verify = await ed25519.verify(sig, signing_data, client_public_key);

  console.log(sig_verify);

  res.set({
    "Access-Control-Allow-Origin": "*"
  });

  res.send({ srr_verify, public_key_verify, sig_verify });
});

// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
