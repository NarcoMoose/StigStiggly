// Rule table filtering: free-text search + status/severity filter chips.
(function () {
  const table = document.getElementById("rule-table");
  if (!table) return;

  const search = document.getElementById("rule-search");
  const counter = document.getElementById("visible-count");
  const ruleRows = Array.from(table.querySelectorAll(".rule-row"));
  const sectionRows = Array.from(table.querySelectorAll(".section-row"));
  const filters = { status: "", severity: "" };

  function apply() {
    const q = (search.value || "").trim().toLowerCase();
    let visible = 0;
    const visibleBySection = {};
    for (const row of ruleRows) {
      const show =
        (!filters.status || row.dataset.status === filters.status) &&
        (!filters.severity || row.dataset.severity === filters.severity) &&
        (!q || row.dataset.text.includes(q));
      row.hidden = !show;
      if (show) {
        visible++;
        visibleBySection[row.dataset.section] = true;
      }
    }
    for (const row of sectionRows) {
      row.hidden = !visibleBySection[row.dataset.section];
    }
    counter.textContent = "Showing " + visible + " of " + ruleRows.length + " rules";
  }

  for (const group of document.querySelectorAll(".filter-group")) {
    group.addEventListener("click", (e) => {
      const btn = e.target.closest(".fbtn");
      if (!btn) return;
      filters[group.dataset.filter] = btn.dataset.value;
      group.querySelectorAll(".fbtn").forEach((b) => b.classList.toggle("active", b === btn));
      apply();
    });
  }
  search.addEventListener("input", apply);
  apply();
})();
