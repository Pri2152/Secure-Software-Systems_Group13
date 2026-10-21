"use strict";

// Isolated browser-controller test; HTTP security is exercised separately by Flask tests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(process.argv[2], "utf8");

async function scenario(failed, hideAt) {
  const handlers = {};
  const requests = [];
  const button = {disabled: false};
  const error = {textContent: ""};
  const root = {
    children: [{textContent: "Candidate Alpha / Example Party"}],
    replaceChildren() { this.children = []; },
    append(...children) { this.children.push(...children); }
  };
  const form = {
    action: "/vote/ballots", selection: "42", resetCount: 0,
    reportValidity() { return true; },
    querySelector() { return button; },
    addEventListener(name, handler) { handlers[name] = handler; },
    reset() { this.selection = null; this.resetCount++; }
  };
  const document = {
    title: "Cast your vote",
    querySelector(selector) {
      return {"#voting-content": root, "#ballot-form": form,
              "#voting-error": error, 'meta[name="csrf-token"]': {content: "csrf-token"}}[selector];
    },
    createElement() { return {textContent: ""}; }
  };
  const context = {
    document,
    window: {addEventListener(name, handler) { handlers[name] = handler; }},
    FormData: class { constructor(value) { this.form = value; } get() { return this.form.selection; } },
    fetch: async (path, options) => {
      requests.push({path, options});
      if (requests.length === 1) {
        if (hideAt === "issue") handlers.pagehide();
        return {ok: !failed, json: async () => ({credential: "A".repeat(43)})};
      }
      if (hideAt === "ballot") handlers.pagehide();
      return {ok: true, json: async () => ({
        status: "accepted", confirmation_reference: "conf_" + "B".repeat(32),
        candidate_id: 42, ballot_id: "must-not-display", ciphertext: "must-not-display"
      })};
    }
  };
  for (const name of ["localStorage", "sessionStorage", "console"]) {
    Object.defineProperty(context, name, {get() { throw new Error("Forbidden persistence/logging"); }});
  }
  vm.runInNewContext(source, context);
  const pending = handlers.submit({preventDefault() {}});
  await handlers.submit({preventDefault() {}}); // Busy guard must reject a second click.
  await pending;
  assert.equal(requests.length, failed || hideAt === "issue" ? 1 : 2);
  assert.deepEqual(JSON.parse(requests[0].options.body), {});
  for (const request of requests) {
    assert.equal(request.options.method, "POST");
    assert.equal(request.options.cache, "no-store");
    assert.equal(request.options.headers["X-CSRFToken"], "csrf-token");
    assert.equal(request.options.credentials, "same-origin");
    assert(!request.path.includes("A".repeat(43)));
  }
  if (!failed && !hideAt) {
    assert.deepEqual(JSON.parse(requests[1].options.body), {credential: "A".repeat(43), candidate_id: 42});
    assert.deepEqual(root.children.map(child => child.textContent),
                     ["Vote accepted.", "Confirmation: conf_" + "B".repeat(32)]);
    assert.equal(form.selection, null);
  } else if (failed) {
    assert(error.textContent.includes("could not be completed"));
    assert(!error.textContent.includes("conf_"));
  } else {
    assert.deepEqual(root.children, []);
  }
  assert.equal(button.disabled, false);
  handlers.pagehide();
  assert.deepEqual(root.children, []);
  assert.equal(form.selection, null);
}

(async () => {
  await scenario(false);
  await scenario(true);
  await scenario(false, "issue");
  await scenario(false, "ballot");
})().catch(error => {
  process.stderr.write(String(error));
  process.exitCode = 1;
});
