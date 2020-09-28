"use strict";
const $ = document.querySelector.bind(document);
const $$ = document.querySelectorAll.bind(document);
EventTarget.prototype.on = EventTarget.prototype.addEventListener;

function base64decode(str) {
  return new Uint8Array([...atob(str)].map(a => a.charCodeAt(0)));
}

function sleep(ms) {
  return new Promise((done, fail) => {
    setTimeout(done, ms);
  });
}

async function progress(message) {
  $(message).style.display = "revert";
  await sleep(1000);
}

document.on("DOMContentLoaded", async e => {
  console.log(e);

  const ISSUER = "https://trust-token-issuer.glitch.me";

  async function verify_human(e) {
    e.preventDefault();
    $("dialog").showModal();

    await progress("#checking");

    // check token exists
    const token = await document.hasTrustToken(ISSUER);
    console.log(token);

    await progress("#hasTrustToken");

    if (token === false) {
      // no token
      await progress("#go2issuer");
    } else {
      await progress("#found");

      try {
        await progress("#redemption");

        // redemption request
        await fetch(`${ISSUER}/.well-known/trust-token/redemption`, {
          method: "POST",
          trustToken: {
            type: "srr-token-redemption",
            issuer: ISSUER
            // refreshPolicy: "refresh"
          }
        });
      } catch (err) {
        await progress("#cached");

        console.info(err);
      }

      await progress("#verify");

      // send SRR to the redeemer server
      const res = await fetch(`/.well-known/trust-token/send-srr`, {
        method: "POST",
        trustToken: {
          type: "send-srr",
          issuer: ISSUER, // deprecated
          issuers: [ISSUER]
        }
      });
      const body = await res.text();
      console.log(body);
      await progress("#finish");

      $("dialog").close();
      $("summary").removeEventListener("click", verify_human)
      e.target.click()
    }
  }

  $("summary").on("click", verify_human);
});
