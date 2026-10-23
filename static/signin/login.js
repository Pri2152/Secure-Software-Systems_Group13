"use strict";

(() => {
  const form = document.querySelector("#signin-form");
  const error = document.querySelector("#signin-error");
  const step1 = document.querySelector("#step-1");
  const step2 = document.querySelector("#step-2");
  const label1 = document.querySelector("#step-label-1");
  const label2 = document.querySelector("#step-label-2");
  const next = document.querySelector("#next");
  const back = document.querySelector("#back");
  const submit = document.querySelector("#submit");
  const showPassword = document.querySelector("#show-password");
  let step = 1;
  let busy = false;

  const messageFor = (status) => {
    if (status === 429) return "Too many attempts. Please wait a few minutes and try again.";
    if (status === 403) return "Access from this device is not allowed.";
    if (status === 401) return "Sign-in failed. Check your details and the current code, then try again.";
    return "Something went wrong. Please try again.";
  };

  const show = (number) => {
    step = number;
    step1.hidden = number !== 1;
    step2.hidden = number !== 2;
    label1.removeAttribute("aria-current");
    label2.removeAttribute("aria-current");
    (number === 1 ? label1 : label2).setAttribute("aria-current", "step");
    error.textContent = "";
    (number === 1 ? form.elements.account_id : form.elements.totp_code).focus();
  };

  const goNext = () => {
    const ready = form.elements.account_id.checkValidity() &&
      form.elements.password.checkValidity();
    if (!ready) {
      error.textContent = "Enter your account and password first.";
      return;
    }
    show(2);
  };

  showPassword.addEventListener("change", () => {
    form.elements.password.type = showPassword.checked ? "text" : "password";
  });
  next.addEventListener("click", goNext);
  back.addEventListener("click", () => show(1));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (step === 1) {
      goNext();
      return;
    }
    if (busy) return;
    if (!form.elements.totp_code.checkValidity()) {
      error.textContent = "Enter the 6-digit code from your authenticator app.";
      return;
    }

    busy = true;
    submit.disabled = true;
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
      form.elements.totp_code.value = "";
      error.textContent = messageFor(typeof status === "number" ? status : 0);
      form.elements.totp_code.focus();
    } finally {
      busy = false;
      submit.disabled = false;
    }
  });
})();
