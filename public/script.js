"use strict";
const $ = document.querySelector.bind(document);
const $$ = document.querySelectorAll.bind(document);
EventTarget.prototype.on = EventTarget.prototype.addEventListener;

function base64decode(str) {
  return new Uint8Array([...atob(str)].map(a => a.charCodeAt(0)));
}

document.on("DOMContentLoaded", async e => {
  console.log(e);

  const ISSUER = "https://trust-token-issuer.glitch.me";

  $("summary").on("click", async e => {
    e.preventDefault();

    $("dialog").showModal();

    // check token exists
    const token = await document.hasTrustToken(ISSUER);
    console.log(token);

    if (token === false) {
      // no token
      $("#go2issuer").style.display = "revert";
    } else {
      // redemption request
      await fetch(`${ISSUER}/.well-known/trust-token/redemption`, {
        method: "POST",
        trustToken: {
          type: "srr-token-redemption",
          issuer: ISSUER,
          // refreshPolicy: "refresh"
        }
      });

      // send SRR and echo Sec-Signed-Eedemption-Record
      const res = await fetch(`${ISSUER}/.well-known/trust-token/send-srr`, {
        method: "POST",
        trustToken: {
          type: "send-srr",
          issuer: ISSUER, // deprecated
          issuers: [ISSUER]
        }
      });
      const body = await res.text();
      console.log(body);

      // TODO: structured-header decode
      const base64 = atob(body.match(/redemption-record=:(.*):/)[1])
        .split(",")[0]
        .match(/body=:(.*):/)[1];
      const bytes = base64decode(base64);
      const result = CBOR.decode(bytes.buffer);

      $("textarea").value = JSON.stringify(result, " ", " ");
    }
  });

  $("summary").click();
});
