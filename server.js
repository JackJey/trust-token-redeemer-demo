const express = require("express");
const app = express();
const cbor = require("cbor");
const sh = require("structured-headers");
const ed25519 = require("ed25519");
const fetch = require("node-fetch");

const { trust_token } = require("./package.json");

app.use(express.static("public"));

app.get("/", async (request, response) => {
  response.sendFile(__dirname + "/views/index.html");
});

function parseSRR(str) {
  return sh.parseList(str).map(srr => {
    const issuer = srr.value;
    const redemption_record = sh.parseDictionary(
      srr["parameters"]["redemption-record"].toString()
    );

    const result = {
      issuer: srr.value,
      record: {
        body: cbor.decodeAllSync(redemption_record.body.value).pop(),
        body_raw: redemption_record.body.value,
        signature: redemption_record.signature.value
      }
    };

    return result;
  });
}

app.post(`/.well-known/trust-token/send-srr`, async (req, res) => {
  console.log(req.path);
  const sec_signed_redemption_record =
    req.headers["sec-signed-redemption-record"];
  res.set({
    "Access-Control-Allow-Origin": "*"
  });

  const signed_redemption_records = parseSRR(sec_signed_redemption_record);
  const { ISSUER } = trust_token;
  const srr = signed_redemption_records
    .filter(({ issuer }) => issuer == ISSUER)
    .pop();

  console.log(srr);

  const key_commitment = await (await fetch(
    "https://trust-token-issuer.glitch.me/.well-known/trust-token/key-commitment"
  )).json();

  // verify
  const signature = srr.record.signature;

  const keystr =
    key_commitment["COMMITMENT"]["https://trust-token-issuer.glitch.me"][
      "srrkey"
    ];
  const public_key = Buffer.from(keystr, "base64");
  const message = srr.record.body_raw;
  console.log(ed25519.Verify(message, signature, public_key));

  res.send(srr);
});

// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
