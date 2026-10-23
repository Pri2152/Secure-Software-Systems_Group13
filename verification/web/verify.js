(function () {
  "use strict";

  var tokenInput = document.getElementById("token");
  var form = document.getElementById("token-form");
  var publishButton = document.getElementById("publish");
  var verifyButton = document.getElementById("verify");
  var message = document.getElementById("message");
  var outcome = document.getElementById("outcome");

  function say(text, isError) {
    message.textContent = text;
    message.className = isError ? "message error" : "message";
  }

  function busy(on) {
    publishButton.disabled = on;
    verifyButton.disabled = on;
  }

  function call(path, method) {
    return fetch(path, {
      method: method,
      headers: { Authorization: "Bearer " + tokenInput.value },
      credentials: "omit"
    });
  }

  function text(tag, value, className) {
    var node = document.createElement(tag);
    node.textContent = value;
    if (className) { node.className = className; }
    return node;
  }

  function showChecks(data) {
    var list = document.getElementById("checks");
    list.replaceChildren();

    data.checks.forEach(function (item) {
      var row = document.createElement("li");
      row.appendChild(text("span", item.passed ? "PASS" : "FAIL",
        "tag " + (item.passed ? "ok" : "bad")));
      row.appendChild(text("span", item.name));
      list.appendChild(row);
    });
  }

  function showTotals(data) {
    var box = document.getElementById("totals");
    box.replaceChildren();

    Object.keys(data.divisions).sort().forEach(function (division) {
      var table = document.createElement("table");
      table.appendChild(text("caption", division));

      var head = document.createElement("tr");
      head.appendChild(text("th", "Candidate"));
      head.appendChild(text("th", "Votes", "num"));
      table.appendChild(head);

      var counts = data.divisions[division];
      Object.keys(counts).sort(function (a, b) { return a - b; }).forEach(function (id) {
        var row = document.createElement("tr");
        row.appendChild(text("td", "Candidate " + id));
        row.appendChild(text("td", String(counts[id]), "num"));
        table.appendChild(row);
      });

      box.appendChild(table);
    });
  }

  function show(data) {
    var banner = document.getElementById("banner");
    banner.textContent = data.all_passed
      ? "All checks passed. The published count is genuine."
      : "Verification failed. Do not trust this count.";
    banner.className = "banner " + (data.all_passed ? "ok" : "bad");

    document.getElementById("election").textContent = data.election_id;
    document.getElementById("version").textContent = String(data.version);
    document.getElementById("ballots").textContent = String(data.ballots_counted);
    document.getElementById("commitment").textContent = data.commitment;

    showChecks(data);
    showTotals(data);
    outcome.hidden = false;
  }

  function failure(response) {
    if (response.status === 401) { return "That token was not accepted."; }
    if (response.status === 404) { return "Nothing has been published yet. Use Count and publish first."; }
    if (response.status === 409) { return "The count was refused because a ballot failed its integrity check."; }
    return "The server could not do that (" + response.status + ").";
  }

  function verify() {
    return call("/bulletin/checks", "GET").then(function (response) {
      if (!response.ok) {
        outcome.hidden = true;
        say(failure(response), true);
        return;
      }
      return response.json().then(function (data) {
        show(data);
        say("Checked just now.", false);
      });
    });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    busy(true);
    say("Checking...", false);
    verify().catch(function () { say("Could not reach the tally service.", true); })
      .then(function () { busy(false); });
  });

  publishButton.addEventListener("click", function () {
    if (!form.reportValidity()) { return; }
    busy(true);
    say("Counting the ballots...", false);

    call("/publish", "POST").then(function (response) {
      if (!response.ok) {
        outcome.hidden = true;
        say(failure(response), true);
        return;
      }
      return verify();
    }).catch(function () { say("Could not reach the tally service.", true); })
      .then(function () { busy(false); });
  });
})();
