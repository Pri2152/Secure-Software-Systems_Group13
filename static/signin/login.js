"use strict";

(() => {
  const form = document.querySelector("#signin-form");
  const error = document.querySelector("#signin-error");
  const button = form.querySelector("button");
  let busy = false;

  const messageFor = (status) => {
    if (status === 429) return "Too many attempts. Please wait a few minutes and try again.";
    if (status === 403) return "Access from this device is not allowed.";
    return "Sign-in failed. Check your details and try again.";
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    busy = true;
    button.disabled = true;
    error.textContent = "";

    try {
      const tokenReply = await fetch("/login/csrf", {
        credentials: "same-origin", cache: "no-store",
        headers: {"Accept": "application/json"}
      });
      if (!tokenReply.ok) throw tokenReply.status;
      const {csrf_token} = await tokenReply.json();

      const data = new FormData(form);
      const reply = await fetch("/login", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "X-CSRFToken": csrf_token
        },
        body: JSON.stringify({
          account_id: data.get("account_id"),
          password: data.get("password"),
          totp_code: data.get("totp_code")
        })
      });
      if (!reply.ok) throw reply.status;

      form.reset();
      window.location.assign("/vote");
    } catch (status) {
      form.elements.password.value = "";
      form.elements.totp_code.value = "";
      error.textContent = messageFor(typeof status === "number" ? status : 0);
    } finally {
      busy = false;
      button.disabled = false;
    }
  });
})();
