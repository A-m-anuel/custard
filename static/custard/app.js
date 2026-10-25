/* CuSTaRD client behaviour. Served from 'self' (strict CSP); no inline scripts anywhere. */
(function () {
  "use strict";

  var PILLARS = [["C", "Confidentiality"], ["I", "Integrity"], ["A", "Availability"]];

  // Mirrors custard/inventory/scoring.py for an instant preview. The server always recomputes
  // the score; the value shown here is never submitted.
  function score(boxes) {
    var per = {}, applicable = [];
    PILLARS.forEach(function (p) { per[p[0]] = { done: 0, total: 0 }; });
    boxes.forEach(function (b) {
      var p = per[b.getAttribute("data-pillar")];
      if (!p) { return; }
      p.total += 1;
      if (b.checked) { p.done += 1; }
    });
    var result = {};
    PILLARS.forEach(function (p) {
      var t = per[p[0]];
      result[p[0]] = t.total ? (t.done / t.total) * 10 : null;
      if (t.total) { applicable.push(result[p[0]]); }
    });
    result.overall = applicable.length
      ? applicable.reduce(function (a, b) { return a + b; }, 0) / applicable.length : null;
    return result;
  }

  function fmt(v) { return v === null ? "—" : (Math.round(v * 100) / 100).toFixed(2); }

  function updatePreview(container, preview) {
    if (!preview) { return; }
    var boxes = Array.prototype.slice.call(container.querySelectorAll("input[type=checkbox][data-pillar]"));
    var s = score(boxes);
    var threshold = parseFloat(preview.getAttribute("data-threshold") || "5");
    var big = preview.querySelector("[data-score=overall]");
    big.textContent = fmt(s.overall);
    big.className = "big " + (s.overall === null ? "" : s.overall < threshold ? "score exposed" : "score ok");
    PILLARS.forEach(function (p) {
      var el = preview.querySelector("[data-score=" + p[0] + "]");
      if (el) { el.textContent = fmt(s[p[0]]); }
    });
    var status = preview.querySelector("[data-status]");
    if (status) {
      status.textContent = s.overall === null ? "" : s.overall < threshold ? "Exposed" : "At or above threshold";
      status.className = "badge " + (s.overall === null ? "unassessed" : s.overall < threshold ? "exposed" : "ok");
    }
  }

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  // Asset registration: render the checklist of the chosen category (dissertation Fig. 29/49).
  function initRegistration() {
    var dataNode = document.getElementById("checklist-data");
    var select = document.getElementById("id_category");
    var target = document.getElementById("checklist");
    var flag = document.getElementById("checklist_submitted");
    var preview = document.getElementById("score-preview");
    if (!dataNode || !select || !target) { return; }
    var data = JSON.parse(dataNode.textContent);
    var previouslyChecked = {};
    (target.getAttribute("data-checked") || "").split(",").forEach(function (v) { if (v) { previouslyChecked[v] = true; } });

    function render() {
      target.textContent = "";
      var items = data[select.value] || [];
      if (!items.length) {
        flag.value = "0";
        if (preview) { preview.classList.add("hidden"); }
        target.appendChild(el("p", { "class": "muted" }, select.value
          ? "This category has no checklist yet. You can assess the asset later."
          : "Choose a category to see its security checklist."));
        return;
      }
      flag.value = "1";
      if (preview) { preview.classList.remove("hidden"); }
      PILLARS.forEach(function (p) {
        var group = items.filter(function (i) { return i.pillar === p[0]; });
        if (!group.length) { return; }
        var fs = el("fieldset");
        fs.appendChild(el("legend", {}, p[1]));
        group.forEach(function (item) {
          var id = "chk-" + item.id;
          var label = el("label", { "for": id });
          var box = el("input", { type: "checkbox", name: "checklist", value: String(item.id), id: id, "data-pillar": item.pillar });
          if (previouslyChecked[String(item.id)]) { box.checked = true; }
          label.appendChild(box);
          label.appendChild(el("span", {}, item.text));
          fs.appendChild(label);
        });
        target.appendChild(fs);
      });
      updatePreview(target, preview);
    }
    select.addEventListener("change", function () { previouslyChecked = {}; render(); });
    target.addEventListener("change", function () { updatePreview(target, preview); });
    var noscript = document.getElementById("checklist-noscript");
    if (noscript) { noscript.classList.add("hidden"); }
    render();
  }

  // Reassessment page: checkboxes are server-rendered; just keep the preview live.
  function initAssessment() {
    var container = document.getElementById("assessment-checklist");
    var preview = document.getElementById("score-preview");
    if (!container || !preview) { return; }
    container.addEventListener("change", function () { updatePreview(container, preview); });
    updatePreview(container, preview);
  }

  // <form data-confirm="Are you sure?">
  function initConfirm() {
    document.addEventListener("submit", function (e) {
      var msg = e.target.getAttribute && e.target.getAttribute("data-confirm");
      if (msg && !window.confirm(msg)) { e.preventDefault(); }
    });
  }

  // <select data-autosubmit> submits its form on change.
  function initAutosubmit() {
    document.querySelectorAll("select[data-autosubmit]").forEach(function (s) {
      s.addEventListener("change", function () { s.form.submit(); });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initRegistration();
    initAssessment();
    initConfirm();
    initAutosubmit();
  });
})();
