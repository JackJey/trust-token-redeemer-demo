/* Copyright 2020 Google LLC. SPDX-License-Identifier: Apache-2.0 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as sfv from "structured-field-values";
import cbor from "cbor";
import ed25519 from "noble-ed25519";
import express from "express";
import secp256r1 from 'secp256r1';


const { trust_token } = JSON.parse(fs.readFileSync("./package.json"));

const __dirname = path.dirname(new URL(import.meta.url).pathname);

const app = express();

app.use(express.static("public"));

app.get("/", async (request, response) => {
  response.sendFile(__dirname + "/views/index.html");
});

app.post(`/.well-known/trust-token/send-rr`, async (req, res) => {
  console.log(req.path);

  const headers = req.headers;
  console.log({ headers });

  // sec-redemption-record
  // [(<issuer 1>, {"redemption-record": <SRR 1>}),
  //  (<issuer N>, {"redemption-record": <SRR N>})],
  const rr = sfv.decodeList(headers["sec-redemption-record"]);
  console.log({ rr })

  const { value, params } = rr[0];
  const redemption_record = Buffer.from(params["redemption-record"]).toString();
  console.log({ redemption_record });

  // verify client_public_key
  const sec_signature = sfv.decodeDict(headers["sec-signature"]);
  console.log({ sec_signature });

  const signatures = sec_signature.signatures.value[0];
  const client_public_key = signatures.params["public-key"];
  console.log({ client_public_key });
  const sig = signatures.params["sig"];
  console.log({ sig });

  const destination = "trust-token-redeemer-demo.glitch.me";

  // verify sec-signature
  const canonical_request_data = new Map([
    ["sec-time", headers["sec-time"]],
    ["public-key", client_public_key],
    ["destination", destination],
    ["sec-redemption-record", headers["sec-redemption-record"]],
    [
      "sec-trust-tokens-additional-signing-data",
      headers["sec-trust-tokens-additional-signing-data"]
    ]
  ]);

  const cbor_data = cbor.encode(canonical_request_data);
  const prefix = Buffer.from("TrustTokenV3");
  const signing_data = Buffer.concat([prefix, cbor_data]);
  
  console.log({
    sig,
    signing_data,
    client_public_key,
    sig_len: sig.length,
    signing_data_len: signing_data.length,
    client_public_key_len: client_public_key.length
  })
  
  const sig_verify = secp256r1.verify(signing_data, Buffer.from(sig), Buffer.from(client_public_key));

  console.log(sig_verify);

  res.set({
    "Access-Control-Allow-Origin": "*"
  });

  res.send({ sig_verify });
});

// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
