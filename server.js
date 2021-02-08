/* Copyright 2020 Google LLC. SPDX-License-Identifier: Apache-2.0 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as sfv from "structured-field-values";
import cbor from "cbor";
import ed25519 from "noble-ed25519";
import express from "express";

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
  console.log(headers);

  // sec-redemption-record
  // [(<issuer 1>, {"redemption-record": <SRR 1>}),
  //  (<issuer N>, {"redemption-record": <SRR N>})],
  const rr = sfv.decodeList(headers["sec-redemption-record"]);
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
  const canonical_request_data = cbor.encode(
    new Map([
      ["sec-time", headers["sec-time"]],
      ["public-key", client_public_key],
      ["destination", destination],
      ["sec-redemption-record", headers["sec-redemption-record"]],
      [
        "sec-trust-tokens-additional-signing-data",
        headers["sec-trust-tokens-additional-signing-data"]
      ]
    ])
  );
  console.log(cbor.decode(canonical_request_data));

  const prefix = Buffer.from("TrustTokenV2");
  const signing_data = Buffer.concat([prefix, canonical_request_data]);
  const sig_verify = await ed25519.verify(sig, signing_data, client_public_key);

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
