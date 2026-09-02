// Baseline builder: rule filtering, selection management, create+generate submit.
(function () {
  const rules = Array.from(document.querySelectorAll(".brule"));
  if (!rules.length) return;

  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const search = document.getElementById("rule-filter");
  const sevGroup = document.getElementById("sev-filter");
  const tagSelect = document.getElementById("tag-filter");
  const selectedOnly = document.getElementById("selected-only");
  const filterCount = document.getElementById("filter-count");
  const selectedCount = document.getElementById("selected-count");
  const createBtn = document.getElementById("create-btn");
  const createStatus = document.getElementById("create-status");
  let severity = "";

  const checkbox = (row) => row.querySelector(".brule-check");

  function apply() {
    const q = (search.value || "").trim().toLowerCase();
    const tag = tagSelect.value;
    let visible = 0;
    for (const row of rules) {
      const show =
        (!severity || row.dataset.severity === severity) &&
        (!tag || row.dataset.tags.split(" ").includes(tag)) &&
        (!q || row.dataset.text.includes(q)) &&
        (!selectedOnly.checked || checkbox(row).checked);
      row.hidden = !show;
      if (show) visible++;
    }
    for (const section of document.querySelectorAll(".builder-section")) {
      const sectionRules = Array.from(section.querySelectorAll(".brule"));
      const shown = sectionRules.filter((r) => !r.hidden).length;
      section.hidden = shown === 0;
      const selected = sectionRules.filter((r) => checkbox(r).checked).length;
      section.querySelector(".sec-count").textContent = selected + " of " + sectionRules.length + " selected";
    }
    const total = rules.filter((r) => checkbox(r).checked).length;
    filterCount.textContent = "Showing " + visible + " of " + rules.length + " rules";
    selectedCount.textContent = total + " rules selected";
  }

  search.addEventListener("input", apply);
  tagSelect.addEventListener("change", apply);
  selectedOnly.addEventListener("change", apply);
  sevGroup.addEventListener("click", (e) => {
    const btn = e.target.closest(".fbtn");
    if (!btn) return;
    severity = btn.dataset.value;
    sevGroup.querySelectorAll(".fbtn").forEach((b) => b.classList.toggle("active", b === btn));
    apply();
  });
  rules.forEach((row) => checkbox(row).addEventListener("change", apply));

  for (const section of document.querySelectorAll(".builder-section")) {
    const set = (value) => (e) => {
      e.preventDefault();
      section.querySelectorAll(".brule:not([hidden]) .brule-check").forEach((c) => (c.checked = value));
      apply();
    };
    section.querySelector(".sec-all").addEventListener("click", set(true));
    section.querySelector(".sec-none").addEventListener("click", set(false));
  }

  createBtn.addEventListener("click", async () => {
    const name = document.getElementById("bl-name").value.trim();
    if (!name) return alert("Give the baseline a name first.");
    const selected = rules.filter((r) => checkbox(r).checked);
    if (!selected.length) return alert("Select at least one rule.");
    const odvs = {};
    for (const row of selected) {
      const input = row.querySelector(".odv-input");
      if (input && input.value.trim() !== "") odvs[row.dataset.id] = input.value.trim();
    }
    createBtn.disabled = true;
    createStatus.textContent = "Writing baseline and starting generation…";
    try {
      const resp = await fetch(createBtn.dataset.endpoint, {
        method: "POST",
        headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" },
        body: JSON.stringify({
          template: createBtn.dataset.template,
          name,
          title: document.getElementById("bl-title").value.trim(),
          description: document.getElementById("bl-desc").value.trim(),
          rules: selected.map((r) => r.dataset.id),
          odvs,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || resp.statusText);
      window.location = createBtn.dataset.done; // activity panel picks up the job there
    } catch (err) {
      createStatus.textContent = "";
      alert("Could not create baseline: " + err.message);
      createBtn.disabled = false;
    }
  });

  apply();
})();
