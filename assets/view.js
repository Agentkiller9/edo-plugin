/**
 * CTFd._internal.challenge.{data,renderer,preRender,render,postRender,
 * submit} is a shared global every challenge type must set (there's no
 * usable default) — unlike create.js/update.js where this object is not
 * read at all.
 *
 * All of edo's participant-facing behavior (flag boxes, submission,
 * instance panel) is wired up inside postRender() below, NOT as an inline
 * <script> tag in view.html. That's not a style choice — it's required:
 * the participant modal's HTML is inserted via Alpine's x-html directive
 * (core-beta's challenges.html: x-html="$store.challenge.data.view"),
 * and per the DOM spec, <script> tags inserted through .innerHTML (which
 * is what x-html does under the hood) are silently never executed by the
 * browser. An inline <script> in view.html only ever ran for CTFd's
 * ADMIN "Preview challenge" feature, which inserts the same markup via
 * jQuery's .append() instead — jQuery specifically extracts and evals
 * <script> tags, unlike raw innerHTML — which is why isolated testing of
 * that path could look like it worked while the real participant flow
 * silently did nothing.
 *
 * postRender() genuinely does fire after every challenge display (both
 * the participant flow, via CTFd.pages.challenge.displayChallenge in
 * CTFd's bundled JS, and the admin preview flow, via challenge.js) — but
 * for the participant flow it can fire before Alpine has actually
 * painted the x-html content, so it defers one tick via Alpine.nextTick.
 */
CTFd._internal.challenge.data = undefined;

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function () {};

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () {
  var chalId = CTFd._internal.challenge.data && CTFd._internal.challenge.data.id;
  if (!chalId) return;
  var run = function () { initEdoChallenge(chalId); };
  if (window.Alpine && Alpine.nextTick) {
    Alpine.nextTick(run);
  } else {
    setTimeout(run, 0);
  }
};

CTFd._internal.challenge.submit = function (preview) {
  var challenge_id = parseInt(CTFd.lib.$("#challenge-id").val());
  var submission = CTFd.lib.$("#challenge-input").val();

  var body = {
    challenge_id: challenge_id,
    submission: submission,
  };
  var params = {};
  if (preview) {
    params["preview"] = true;
  }

  return CTFd.api.post_challenge_attempt(params, body).then(function (response) {
    return response;
  });
};

// Timer for the instance panel's live countdown — module-scoped so a
// re-open of the modal (or opening a different challenge) can clear the
// previous one instead of leaking an interval that just writes into a
// detached DOM node forever.
var _edoInstanceTimer = null;

function initEdoChallenge(chalId) {
  var flagsContainer = document.getElementById("edo-flags-container");
  var alertBox = document.getElementById("edo-submit-alert");
  var panel = document.getElementById("edo-instance-panel");
  var progressEl = document.getElementById("edo-progress");
  if (!flagsContainer || !alertBox || !panel || !progressEl) return;

  if (_edoInstanceTimer) {
    clearInterval(_edoInstanceTimer);
    _edoInstanceTimer = null;
  }

  // style: "success" | "danger" | "info" — "info" is for a resubmission of
  // a flag already credited: still visually distinct from a genuine new
  // find (green), so it doesn't read as "yep, that counted again."
  function showAlert(style, message) {
    alertBox.textContent = message;
    alertBox.className = "alert text-center w-100 alert-" + style;
    alertBox.style.display = "";
  }

  // One input+submit box per flag — makes it visually obvious a 2-flag
  // challenge needs 2 separate submissions, not one box reused twice.
  // Boxes aren't tied to a *specific* flag (we don't disclose which flag
  // is "first"/"second" — any box accepts any not-yet-found flag); the
  // first `solved` boxes just render as done, freeing the rest for
  // whatever's still outstanding.
  function renderFlagBoxes(total, solved) {
    flagsContainer.innerHTML = "";
    for (var i = 0; i < total; i++) {
      var row = document.createElement("div");
      row.className = "row mb-2 edo-flag-row";
      if (i < solved) {
        row.innerHTML =
          '<div class="col-12"><span class="badge bg-success">Flag ' + (i + 1) + ' found ✓</span></div>';
      } else {
        row.innerHTML =
          '<div class="col-12 col-sm-8">' +
          '<input class="form-control edo-flag-input" type="text" placeholder="Flag ' + (i + 1) + '" autocomplete="off">' +
          '</div>' +
          '<div class="col-12 col-sm-4 mt-2 mt-sm-0">' +
          '<button class="btn btn-outline-secondary w-100 h-100 edo-flag-submit" type="button">Submit</button>' +
          '</div>';
      }
      flagsContainer.appendChild(row);
    }
  }

  async function submitFlag(row) {
    var input = row.querySelector(".edo-flag-input");
    var btn = row.querySelector(".edo-flag-submit");
    var submission = input.value;
    if (!submission) return;
    btn.disabled = true;
    try {
      var res = await CTFd.fetch(`/plugins/edo_plugin/challenges/${chalId}/submit`, {
        method: "POST",
        body: JSON.stringify({ submission: submission }),
      });
      var j = await res.json();
      if (!j.success) {
        showAlert("danger", j.error === "rate_limited"
          ? `Too many attempts — try again in ${j.retry_after}s`
          : j.error === "attempts_exhausted"
          ? "No attempts remaining."
          : (j.error || "Something went wrong."));
        return;
      }
      showAlert(j.already_found ? "info" : (j.correct ? "success" : "danger"), j.message);
      if (j.correct && !j.already_found) {
        refreshProgress();  // re-renders boxes, collapsing this one to a checkmark
      }
    } finally {
      btn.disabled = false;
    }
  }

  // Event delegation on the container — boxes get replaced wholesale on
  // every refreshProgress(), so listeners bound directly to them would
  // go stale. This binds fresh each time initEdoChallenge() runs (i.e.
  // each time the modal opens), against that open's own container node.
  flagsContainer.addEventListener("click", function (e) {
    var btn = e.target.closest(".edo-flag-submit");
    if (btn) submitFlag(btn.closest(".edo-flag-row"));
  });
  flagsContainer.addEventListener("keyup", function (e) {
    if (e.key === "Enter" && e.target.classList.contains("edo-flag-input")) {
      submitFlag(e.target.closest(".edo-flag-row"));
    }
  });

  var status = panel.querySelector(".edo-instance-status");
  var spawn = panel.querySelector(".edo-spawn");
  var stop = panel.querySelector(".edo-stop");
  var extend = panel.querySelector(".edo-extend");

  // Event delegation — the copy button gets recreated every tick() (the
  // countdown re-renders status.innerHTML every second), so a listener
  // bound directly to it would go stale after the very first tick.
  panel.addEventListener("click", async function (e) {
    var btn = e.target.closest(".edo-copy-target");
    if (!btn) return;
    try {
      await navigator.clipboard.writeText(btn.dataset.target);
      var original = btn.innerHTML;
      btn.innerHTML = '<i class="fa-solid fa-check"></i>';
      setTimeout(function () { btn.innerHTML = original; }, 1200);
    } catch (err) {
      // Clipboard API unavailable (e.g. insecure context) — nothing
      // reasonable to fall back to here, fail silently.
    }
  });

  var challengeData = CTFd._internal.challenge.data || {};
  var category = challengeData.category || "";
  var accessMode = challengeData.access_mode || "vpn";
  // Only known after the first dashboard/data fetch (refresh(), below) —
  // it's a global admin setting, not part of the challenge/instance data.
  var publicIp = null;

  // Category-based display rule: B2R challenges show just the host, no
  // port — everything else shows host:port as usual.
  function endpointText(inst) {
    var host, port;
    if (accessMode === "public") {
      host = publicIp || "?";
      port = firstPublishedPort(inst);
    } else {
      host = inst.assigned_ip || "?";
      port = firstExposedPort(inst);
    }
    if (category === "B2R" || port == null) {
      return host;
    }
    return `${host}:${port}`;
  }

  function firstExposedPort(inst) {
    // access_mode="vpn": a list of ports the container listens on
    // (Dockerfile EXPOSE) — connect directly to assigned_ip on these, no
    // host-port mapping.
    try {
      var ports = JSON.parse(inst.host_ports || "[]");
      return ports.length ? ports[0].split("/")[0] : null;
    } catch (e) {
      return null;
    }
  }

  function firstPublishedPort(inst) {
    // access_mode="public": {container_port: host_port, ...} — the real
    // host port Docker bound for this owner's container.
    try {
      var map = JSON.parse(inst.published_ports || "{}");
      var keys = Object.keys(map);
      return keys.length ? map[keys[0]] : null;
    } catch (e) {
      return null;
    }
  }

  function render(inst) {
    if (!inst) {
      status.textContent = "No instance running.";
      spawn.style.display = "";
      stop.style.display = "none";
      extend.style.display = "none";
      if (_edoInstanceTimer) { clearInterval(_edoInstanceTimer); _edoInstanceTimer = null; }
      return;
    }
    spawn.style.display = "none";
    stop.style.display = "";
    extend.style.display = "";
    extend.disabled = !inst.can_extend;

    var remaining = inst.remaining_seconds;
    function tick() {
      var m = String(Math.floor(remaining / 60)).padStart(2, "0");
      var s = String(remaining % 60).padStart(2, "0");
      var target = endpointText(inst);
      status.innerHTML =
        `Target <code>${target}</code> `
        + `<button type="button" class="btn btn-sm btn-outline-secondary edo-copy-target" `
        + `data-target="${target}" title="Copy target"><i class="fa-solid fa-copy"></i></button>`
        + ` · ${m}:${s} remaining`;
      remaining--;
      if (remaining < 0) refresh();
    }
    tick();
    if (_edoInstanceTimer) clearInterval(_edoInstanceTimer);
    _edoInstanceTimer = setInterval(tick, 1000);
  }

  async function refresh() {
    var res = await CTFd.fetch("/plugins/edo_plugin/dashboard/data");
    if (!res.ok) return render(null);
    var j = await res.json();
    if (j.public_ip) publicIp = j.public_ip;
    var inst = (j.instances || []).find(i => String(i.challenge_id) === String(chalId));
    render(inst || null);
  }

  async function refreshProgress() {
    var res = await CTFd.fetch(`/plugins/edo_plugin/challenges/${chalId}/progress`);
    if (!res.ok) {
      renderFlagBoxes(1, 0);  // fallback: at least one usable box
      return;
    }
    var j = await res.json();
    if (!j.success) {
      renderFlagBoxes(1, 0);
      return;
    }
    progressEl.textContent = j.flags_total > 1
      ? `· ${j.flags_solved}/${j.flags_total} flags captured (${j.percent_earned}%)`
      : "";  // single-flag challenges don't need this
    renderFlagBoxes(j.flags_total, j.flags_solved);
  }

  spawn.onclick = async () => {
    spawn.disabled = true;
    var res = await CTFd.fetch(`/plugins/edo_plugin/challenges/${chalId}/instance`, { method: "POST" });
    var j = await res.json();
    if (!j.success) alert(j.error + (j.detail ? `: ${j.detail}` : ""));
    spawn.disabled = false;
    refresh();
  };
  stop.onclick = async () => {
    var inst = await currentInstance();
    if (!inst) return;
    await CTFd.fetch(`/plugins/edo_plugin/instances/${inst.id}`, { method: "DELETE" });
    refresh();
  };
  extend.onclick = async () => {
    var inst = await currentInstance();
    if (!inst) return;
    var res = await CTFd.fetch(`/plugins/edo_plugin/instances/${inst.id}/extend`, { method: "POST" });
    var j = await res.json();
    if (!j.success) alert(j.error);
    refresh();
  };

  async function currentInstance() {
    var res = await CTFd.fetch("/plugins/edo_plugin/dashboard/data");
    var j = await res.json();
    return (j.instances || []).find(i => String(i.challenge_id) === String(chalId));
  }

  refresh();
  refreshProgress();
}
