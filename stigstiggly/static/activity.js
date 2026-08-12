// Actions: scan / remediate (with confirmation modal) / exemptions.
// Live job output is streamed into the activity panel via Server-Sent Events.
(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  async function post(url, body) {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || resp.statusText);
    return data;
  }

  // ---- activity panel + job streaming (overview & baseline pages) --------
  const panel = document.getElementById("activity-panel");
  if (panel) {
    const logEl = document.getElementById("activity-log");
    const statusEl = document.getElementById("activity-status");
    const cmdEl = document.getElementById("activity-cmd");
    const actionButtons = Array.from(document.querySelectorAll(".scan-btn, #fix-open"));
    let source = null;

    const setButtons = (disabled) =>
      actionButtons.forEach((b) => {
        if (!b.dataset.locked) b.disabled = disabled;
      });

    const setStatus = (text, cls) => {
      statusEl.textContent = text;
      statusEl.className = "badge " + cls;
    };

    function attach(job, from) {
      panel.hidden = false;
      cmdEl.textContent = job.command;
      setStatus(job.kind === "fix" ? "remediating" : "scanning", "badge-running");
      setButtons(true);
      if (source) source.close();
      source = new EventSource("/job/" + job.id + "/stream?from=" + (from || 0));
      source.onmessage = (e) => {
        logEl.textContent += JSON.parse(e.data) + "\n";
        logEl.scrollTop = logEl.scrollHeight;
      };
      source.addEventListener("done", (e) => {
        source.close();
        const info = JSON.parse(e.data);
        const ok = info.status === "succeeded";
        if (ok && info.kind === "fix") {
          // Remediation done -> always follow up with a fresh scan so the
          // dashboard reflects the post-fix state.
          logEl.textContent += "\n— remediation complete, starting follow-up scan —\n";
          logEl.scrollTop = logEl.scrollHeight;
          startJob(info.baseline, "scan").catch((err) => {
            setStatus("scan failed to start", "badge-fail");
            setButtons(false);
            alert(err.message);
          });
          return;
        }
        setStatus(ok ? "finished" : "failed" + (info.exit_code !== null ? " (exit " + info.exit_code + ")" : ""),
                  ok ? "badge-pass" : "badge-fail");
        setButtons(false);
        if (ok) {
          logEl.textContent += "\n— complete, refreshing results —\n";
          logEl.scrollTop = logEl.scrollHeight;
          setTimeout(() => location.reload(), 1600);
        }
      });
    }

    async function startJob(baseline, kind) {
      const data = await post("/baseline/" + encodeURIComponent(baseline) + "/" + (kind === "fix" ? "fix" : "scan"));
      attach(data.job, 0);
    }

    document.querySelectorAll(".scan-btn").forEach((btn) =>
      btn.addEventListener("click", () => {
        btn.disabled = true;
        logEl.textContent = "";
        startJob(btn.dataset.baseline, "scan").catch((err) => {
          alert("Could not start scan: " + err.message);
          btn.disabled = false;
        });
      })
    );

    // Remediation goes through the confirmation modal.
    const modal = document.getElementById("fix-modal");
    const fixOpen = document.getElementById("fix-open");
    if (modal && fixOpen) {
      fixOpen.addEventListener("click", () => modal.showModal());
      document.getElementById("fix-cancel").addEventListener("click", () => modal.close());
      document.getElementById("fix-confirm").addEventListener("click", () => {
        modal.close();
        logEl.textContent = "";
        startJob(modal.dataset.baseline, "fix").catch((err) =>
          alert("Could not start remediation: " + err.message)
        );
      });
    }

    // Re-attach to an in-flight job when the page (re)loads.
    fetch("/job")
      .then((r) => r.json())
      .then((data) => {
        if (data.job && data.job.status === "running") attach(data.job, 0);
      })
      .catch(() => {});
  }

  // ---- exemption form (rule page) -----------------------------------------
  const exemptCard = document.getElementById("exempt-card");
  if (exemptCard) {
    const url =
      "/baseline/" + encodeURIComponent(exemptCard.dataset.baseline) +
      "/rule/" + encodeURIComponent(exemptCard.dataset.rule) + "/exempt";
    const setBtn = document.getElementById("exempt-set");
    const clearBtn = document.getElementById("exempt-clear");
    if (setBtn) {
      setBtn.addEventListener("click", () => {
        const reason = document.getElementById("exempt-reason").value.trim();
        if (!reason) return alert("Please provide an exemption reason.");
        setBtn.disabled = true;
        post(url, { exempt: true, reason })
          .then(() => location.reload())
          .catch((err) => {
            alert(err.message);
            setBtn.disabled = false;
          });
      });
    }
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        clearBtn.disabled = true;
        post(url, { exempt: false })
          .then(() => location.reload())
          .catch((err) => {
            alert(err.message);
            clearBtn.disabled = false;
          });
      });
    }
  }
})();
