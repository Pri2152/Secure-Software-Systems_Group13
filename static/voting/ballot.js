"use strict";

(() => {
  const root = document.querySelector("#voting-content");
  const form = document.querySelector("#ballot-form");
  const error = document.querySelector("#voting-error");
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const button = form.querySelector("button");
  let credential = null;
  let busy = false;
  let departed = false;

  const post = (path, body) => fetch(path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {"Content-Type": "application/json", "X-CSRFToken": csrf},
    body: JSON.stringify(body)
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    busy = true;
    button.disabled = true;
    error.textContent = "";
    let candidateId = Number(new FormData(form).get("candidate_id"));
    try {
      const issued = await post("/vote/credentials", {});
      if (!issued.ok) throw new Error();
      credential = (await issued.json()).credential;
      if (departed) return;
      const response = await post(form.action, {credential, candidate_id: candidateId});
      credential = null;
      if (departed) return;
      if (!response.ok) throw new Error();
      const result = await response.json();
      if (departed) return;
      if (result.status !== "accepted" || !/^conf_[A-Za-z0-9_-]{32}$/.test(result.confirmation_reference)) {
        throw new Error();
      }
      form.reset();
      root.replaceChildren();
      document.title = "Vote accepted";
      const title = document.createElement("h1");
      title.textContent = "Vote accepted.";
      const confirmation = document.createElement("p");
      confirmation.textContent = "Confirmation: " + result.confirmation_reference;
      root.append(title, confirmation);
    } catch (_) {
      if (!departed) error.textContent = "Your request could not be completed. If the connection was lost, acceptance may already have occurred. Sign in again to check whether voting is available.";
    } finally {
      credential = null;
      candidateId = null;
      busy = false;
      button.disabled = false;
    }
  });

  window.addEventListener("pagehide", () => {
    departed = true;
    credential = null;
    form.reset();
    root.replaceChildren();
  });
})();
