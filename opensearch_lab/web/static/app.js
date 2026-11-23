/* OpenSearch — Yuhan's LAB Web Dashboard Logic */

let currentReport = null;
let currentSevFilter = "all";
let detectTimer = null;

function escapeHtml(raw) {
  const str = raw == null ? "" : String(raw);
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeUrl(raw) {
  const s = (raw || "").trim();
  if (s.startsWith("http://") || s.startsWith("https://")) return s;
  return "";
}

/* ---------------- Tabs ---------------- */
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    const tabId = btn.dataset.tab;
    document.getElementById(`tab-${tabId}`).classList.add("active");

    if (tabId === "history") loadHistory();
    if (tabId === "watchlist") loadWatchlist();
    if (tabId === "modules") loadModules();
  });
});

/* ---------------- Auto Detect ---------------- */
const queryInput = document.getElementById("query-input");
const typeSelect = document.getElementById("type-select");
const detectPill = document.getElementById("detect-pill");

async function updateDetectPreview() {
  const q = queryInput.value.trim();
  if (!q) {
    detectPill.textContent = "Auto-detect siap";
    return;
  }
  try {
    const res = await fetch(`/api/detect?q=${encodeURIComponent(q)}&type=${encodeURIComponent(typeSelect.value)}`);
    const data = await res.json();
    detectPill.textContent = `Tipe: ${data.target_type}`;
  } catch (_) {}
}

queryInput.addEventListener("input", () => {
  clearTimeout(detectTimer);
  detectTimer = setTimeout(updateDetectPreview, 220);
});
typeSelect.addEventListener("change", updateDetectPreview);

/* Quick demo chips */
document.querySelectorAll(".chip-btn").forEach((chip) => {
  chip.addEventListener("click", () => {
    queryInput.value = chip.dataset.sample || "";
    typeSelect.value = "auto";
    updateDetectPreview();
    queryInput.focus();
  });
});

/* Image Upload Box Toggle */
document.getElementById("toggle-image-btn").addEventListener("click", () => {
  document.getElementById("image-upload-box").classList.toggle("hidden");
});

/* ---------------- Scan Submission ---------------- */
function setLoading(isLoading, text = "Menjalankan modul OSINT secara paralel...") {
  const bar = document.getElementById("loading-bar");
  const err = document.getElementById("error-banner");
  const btn = document.getElementById("scan-btn");
  err.classList.add("hidden");
  if (isLoading) {
    document.getElementById("loading-text").textContent = text;
    bar.classList.remove("hidden");
    btn.disabled = true;
  } else {
    bar.classList.add("hidden");
    btn.disabled = false;
  }
}

function showError(msg) {
  const err = document.getElementById("error-banner");
  err.textContent = msg;
  err.classList.remove("hidden");
}

async function runScan(query, targetType = "auto") {
  setLoading(true, `Memindai '${query}' dengan multi-modul OSINT...`);
  try {
    const payload = {
      query,
      target_type: targetType,
      fast: document.getElementById("fast-mode").checked,
      auto_pivot: document.getElementById("auto-pivot").checked,
      verify_profiles: document.getElementById("verify-profiles").checked,
      maigret_top: parseInt(document.getElementById("maigret-top").value || "80", 10),
    };
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Gagal menjalankan investigasi");
    renderReport(data);
  } catch (e) {
    showError(e.message || String(e));
  } finally {
    setLoading(false);
  }
}

document.getElementById("scan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = queryInput.value.trim();
  if (!q) return;
  runScan(q, typeSelect.value);
});

document.getElementById("scan-image-btn").addEventListener("click", async () => {
  const fileInput = document.getElementById("image-file-input");
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    showError("Pilih file gambar (.jpg/.png/.webp) terlebih dahulu.");
    return;
  }
  setLoading(true, `Menganalisis EXIF & hash bukti gambar '${file.name}'...`);
  try {
    const form = new FormData();
    form.append("image", file);
    const res = await fetch("/api/scan-image", { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Gagal menganalisis gambar");
    renderReport(data);
  } catch (e) {
    showError(e.message || String(e));
  } finally {
    setLoading(false);
  }
});

/* ---------------- Render Report ---------------- */
function riskColor(level) {
  return {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#10b981",
  }[level] || "#06b6d4";
}

function renderReport(report) {
  currentReport = report;
  document.getElementById("results-area").classList.remove("hidden");

  const score = Number(report.risk?.score || 0);
  const level = report.risk?.level || "LOW";
  const color = riskColor(level);

  const arc = document.getElementById("gauge-arc");
  const circumference = 326.7;
  arc.style.stroke = color;
  arc.style.strokeDashoffset = String(circumference - (circumference * Math.min(100, Math.max(0, score))) / 100);

  document.getElementById("risk-score-val").textContent = String(score);
  const badge = document.getElementById("risk-level-badge");
  badge.textContent = level;
  badge.style.background = color;

  document.getElementById("case-id-badge").textContent = report.case_id;
  document.getElementById("result-target-title").textContent = `${report.query} (${report.target_type})`;
  document.getElementById("risk-summary-text").textContent = report.risk?.summary || "";
  document.getElementById("scan-stats-text").textContent =
    `${report.duration_ms} ms • ${report.findings?.length || 0} temuan • ${report.entities?.length || 0} entitas`;
  document.getElementById("case-notes-input").value = report.notes || "";

  // Watchlist banner
  const wlBanner = document.getElementById("watchlist-alert");
  if (report.watchlist_matches && report.watchlist_matches.length > 0) {
    const items = report.watchlist_matches
      .map((m) =>
        m.match_kind === "watchlist"
          ? `<li><strong>[WATCHLIST]</strong> ${escapeHtml(m.indicator)} — ${escapeHtml(m.label)} (${escapeHtml(m.reason || "-")})</li>`
          : `<li><strong>[PRIOR CASE]</strong> ${escapeHtml(m.case_id)} (${escapeHtml(m.prior_query)}, Risk ${escapeHtml(m.risk_score)}/100)</li>`
      )
      .join("");
    wlBanner.innerHTML = `<h3>Peringatan Watchlist &amp; Korelasi Kasus Sebelumnya</h3><ul>${items}</ul>`;
    wlBanner.classList.remove("hidden");
  } else {
    wlBanner.classList.add("hidden");
  }

  // Trust signals
  const trustCard = document.getElementById("trust-signals-card");
  const trustWrap = document.getElementById("trust-signals-list");
  const trusts = report.risk?.trust_signals || [];
  if (trusts.length > 0) {
    trustCard.classList.remove("hidden");
    trustWrap.innerHTML = trusts
      .map(
        (t) => `
      <div class="signal-item">
        <div>
          <div><span class="sev sev-low">TRUST</span> <strong>${escapeHtml(t.label)}</strong></div>
          <div class="muted">${escapeHtml(t.source)}: ${escapeHtml(t.detail)}</div>
        </div>
      </div>`
      )
      .join("");
  } else {
    trustCard.classList.add("hidden");
  }

  // Signals
  const sigWrap = document.getElementById("signals-list");
  const signals = report.risk?.signals || [];
  if (signals.length === 0) {
    sigWrap.innerHTML = `<p class="muted">Tidak ada sinyal red-flag berisiko yang terpicu.</p>`;
  } else {
    sigWrap.innerHTML = signals
      .map(
        (s) => `
      <div class="signal-item">
        <div>
          <div><span class="sev sev-${escapeHtml(s.severity)}">${escapeHtml(s.severity.toUpperCase())}</span> <strong>${escapeHtml(s.label)}</strong></div>
          <div class="muted">${escapeHtml(s.source)}: ${escapeHtml(s.detail)}</div>
        </div>
        <div class="signal-pts">+${escapeHtml(s.points)}</div>
      </div>`
      )
      .join("");
  }

  // Pivots
  const pivWrap = document.getElementById("pivots-list");
  const pivots = report.pivot_suggestions || [];
  if (pivots.length === 0) {
    pivWrap.innerHTML = `<p class="muted">Belum ada kandidat pivot tambahan.</p>`;
  } else {
    pivWrap.innerHTML = pivots
      .map(
        (p, idx) => `
      <div class="pivot-item">
        <div>
          <span class="pivot-type">${escapeHtml(p.type)}</span>
          <strong>${escapeHtml(p.value)}</strong>
          <div class="muted">${escapeHtml(p.reason)}</div>
        </div>
        <button type="button" class="btn btn-primary btn-sm pivot-run-btn" data-pidx="${idx}">Pivot Scan</button>
      </div>`
      )
      .join("");
      pivots.forEach((p, idx) => {});
    pivWrap.querySelectorAll(".pivot-run-btn").forEach((b) => {
      b.addEventListener("click", () => {
        const item = pivots[Number(b.dataset.pidx)];
        if (item) {
          queryInput.value = item.value;
          const mappedType =
            item.type === "full_name"
              ? "name"
              : item.type === "crypto_wallet"
              ? "crypto"
              : item.type === "bank_account"
              ? "bank"
              : item.type;
          typeSelect.value = mappedType;
          updateDetectPreview();
          runScan(item.value, typeSelect.value);
          window.scrollTo({ top: 0, behavior: "smooth" });
        }
      });
    });
  }

  // Findings
  currentSevFilter = "all";
  document.querySelectorAll(".sev-pill").forEach((p) => p.classList.toggle("active", p.dataset.sev === "all"));
  document.getElementById("finding-search").value = "";
  renderFindingsTable();

  // Filtered false positives drawer
  const fpDetails = document.getElementById("fp-audit-details");
  const fps = report.filtered_false_positives || [];
  if (fps.length > 0) {
    fpDetails.classList.remove("hidden");
    document.getElementById("fp-count").textContent = String(fps.length);
    document.getElementById("fp-list").innerHTML =
      "<ul>" +
      fps
        .map(
          (fp) =>
            `<li><code>${escapeHtml(fp.source)}</code>: ${escapeHtml(fp.url || fp.title)} (${escapeHtml(fp.metadata?.filter_reason || "soft-404")})</li>`
        )
        .join("") +
      "</ul>";
  } else {
    fpDetails.classList.add("hidden");
  }

  // Modules Run
  const modGrid = document.getElementById("modules-run-grid");
  modGrid.innerHTML = (report.modules_run || [])
    .map(
      (m) => `
    <div class="mod-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
        <strong>${escapeHtml(m.display_name)}</strong>
        <span class="sev sev-${m.status === "ok" ? "low" : m.status === "partial" ? "medium" : "critical"}">${escapeHtml(m.status.toUpperCase())}</span>
      </div>
      <div class="muted">${escapeHtml(m.module_name)} &bull; ${escapeHtml(m.duration_ms)} ms &bull; ${m.findings?.length || 0} temuan</div>
      <div class="muted" style="margin-top:4px;">${escapeHtml(m.summary || m.error || "")}</div>
    </div>`
    )
    .join("");

  // Draw Entity Graph
  drawEntityGraph(report.graph || { nodes: [], edges: [] });
}

function renderFindingsTable() {
  if (!currentReport) return;
  const search = document.getElementById("finding-search").value.trim().toLowerCase();
  const list = (currentReport.findings || []).filter((f) => {
    if (currentSevFilter !== "all" && f.severity !== currentSevFilter) return false;
    if (search) {
      const hay = `${f.source} ${f.category} ${f.title} ${f.value}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  document.getElementById("findings-count").textContent = String(list.length);
  const wrap = document.getElementById("findings-container");
  if (list.length === 0) {
    wrap.innerHTML = `<p class="muted">Tidak ada temuan cocok dengan filter.</p>`;
    return;
  }
  const rows = list
    .map((f) => {
      const link = safeUrl(f.url);
      const linkHtml = link ? ` <a href="${escapeHtml(link)}" target="_blank" rel="noopener noreferrer">[Buka &nearr;]</a>` : "";
      let vBadge = "";
      if (f.verification_status === "verified" || f.verification_status === "corroborated") {
        vBadge = `<span class="v-badge v-verified">${escapeHtml(f.verification_status.toUpperCase())}</span>`;
      } else if (f.verification_status === "unverified_login_wall") {
        vBadge = `<span class="v-badge v-loginwall">LOGIN-WALL</span>`;
      }
      return `
      <tr>
        <td><span class="sev sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span>${vBadge}</td>
        <td><code>${escapeHtml(f.source)}</code></td>
        <td><strong>${escapeHtml(f.title)}</strong><div class="muted">${escapeHtml(f.category)}</div></td>
        <td>${escapeHtml(f.value)}${linkHtml}</td>
      </tr>`;
    })
    .join("");
  wrap.innerHTML = `<table><thead><tr><th>Severity</th><th>Modul</th><th>Temuan</th><th>Nilai &amp; Tautan</th></tr></thead><tbody>${rows}</tbody></table>`;
}

document.getElementById("finding-search").addEventListener("input", renderFindingsTable);
document.querySelectorAll(".sev-pill").forEach((pill) => {
  pill.addEventListener("click", () => {
    document.querySelectorAll(".sev-pill").forEach((p) => p.classList.remove("active"));
    pill.classList.add("active");
    currentSevFilter = pill.dataset.sev || "all";
    renderFindingsTable();
  });
});

/* ---------------- Exports, Notes & Watchlist Quick Add ---------------- */
document.querySelectorAll(".export-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (!currentReport) return;
    window.location.href = `/api/cases/${encodeURIComponent(currentReport.case_id)}/export/${encodeURIComponent(btn.dataset.fmt)}`;
  });
});

document.getElementById("open-pyvis-btn").addEventListener("click", () => {
  if (!currentReport) return;
  window.open(`/api/cases/${encodeURIComponent(currentReport.case_id)}/graph`, "_blank", "noopener,noreferrer");
});

document.getElementById("save-notes-btn").addEventListener("click", async () => {
  if (!currentReport) return;
  const notes = document.getElementById("case-notes-input").value;
  await fetch(`/api/cases/${encodeURIComponent(currentReport.case_id)}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
  currentReport.notes = notes;
});

document.getElementById("add-watchlist-btn").addEventListener("click", async () => {
  if (!currentReport) return;
  const reason = prompt(`Alasan menandai '${currentReport.query}' sebagai penipu:`, currentReport.risk?.summary || "");
  if (reason === null) return;
  await fetch("/api/watchlist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      indicator: currentReport.query,
      indicator_type: currentReport.target_type,
      label: `Flagged (${currentReport.risk?.level || "SUSPECT"})`,
      reason,
    }),
  });
  alert(`'${currentReport.query}' ditambahkan ke Watchlist Penipu lokal.`);
});

/* ---------------- Canvas Entity Graph ---------------- */
function drawEntityGraph(graph) {
  const canvas = document.getElementById("entity-canvas");
  const ctx = canvas.getContext("2d");
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const rawNodes = (graph.nodes || []).slice(0, 45);
  if (rawNodes.length === 0) {
    ctx.fillStyle = "#94a3b8";
    ctx.font = "14px sans-serif";
    ctx.fillText("Belum ada entitas graf untuk ditampilkan.", 24, 40);
    return;
  }

  const nodeMap = {};
  const cx = W / 2;
  const cy = H / 2;
  const nonRoot = rawNodes.filter((n) => !n.is_root);

  rawNodes.forEach((n) => {
    if (n.is_root) {
      nodeMap[n.id] = { ...n, x: cx, y: cy };
    }
  });
  nonRoot.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, nonRoot.length);
    const radius = i % 2 === 0 ? Math.min(W, H) * 0.34 : Math.min(W, H) * 0.23;
    nodeMap[n.id] = {
      ...n,
      x: cx + Math.cos(angle) * radius * 1.45,
      y: cy + Math.sin(angle) * radius * 0.92,
    };
  });

  // Edges
  ctx.lineWidth = 1.2;
  (graph.edges || []).forEach((e) => {
    const a = nodeMap[e.source];
    const b = nodeMap[e.target];
    if (!a || !b) return;
    ctx.strokeStyle = "rgba(148, 163, 184, 0.35)";
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();

    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    ctx.fillStyle = "#64748b";
    ctx.font = "10px sans-serif";
    ctx.fillText(e.relation, mx + 3, my - 3);
  });

  // Nodes
  Object.values(nodeMap).forEach((n) => {
    const r = n.is_root ? 14 : 9;
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = n.color || "#06b6d4";
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = "#070b14";
    ctx.stroke();

    ctx.fillStyle = "#e2e8f0";
    ctx.font = n.is_root ? "bold 12px sans-serif" : "11px sans-serif";
    const lbl = String(n.label || "").slice(0, 28);
    ctx.fillText(lbl, n.x + r + 5, n.y + 4);
  });
}

/* ---------------- History Tab ---------------- */
async function loadHistory() {
  const search = document.getElementById("history-search").value.trim();
  const res = await fetch(`/api/cases?limit=50&search=${encodeURIComponent(search)}`);
  const data = await res.json();
  const cases = data.cases || [];
  const wrap = document.getElementById("history-list");
  if (cases.length === 0) {
    wrap.innerHTML = `<p class="muted">Belum ada riwayat investigasi.</p>`;
    return;
  }
  const rows = cases
    .map(
      (c) => `
    <tr>
      <td><code>${escapeHtml(c.case_id)}</code></td>
      <td><strong>${escapeHtml(c.query)}</strong></td>
      <td>${escapeHtml(c.target_type)}</td>
      <td><span class="sev sev-${escapeHtml(String(c.risk_level).toLowerCase())}">${escapeHtml(c.risk_score)}/100 (${escapeHtml(c.risk_level)})</span></td>
      <td class="muted">${escapeHtml(String(c.created_at).slice(0, 19))}</td>
      <td>
        <button type="button" class="btn btn-primary btn-sm open-case-btn" data-cid="${escapeHtml(c.case_id)}">Buka</button>
        <button type="button" class="btn btn-danger btn-sm del-case-btn" data-cid="${escapeHtml(c.case_id)}">Hapus</button>
      </td>
    </tr>`
    )
    .join("");
  wrap.innerHTML = `<table><thead><tr><th>Case ID</th><th>Target</th><th>Tipe</th><th>Risiko</th><th>Waktu (UTC)</th><th>Aksi</th></tr></thead><tbody>${rows}</tbody></table>`;

  wrap.querySelectorAll(".open-case-btn").forEach((b) => {
    b.addEventListener("click", async () => {
      const r = await fetch(`/api/cases/${encodeURIComponent(b.dataset.cid)}`);
      const full = await r.json();
      document.querySelector('.tab-btn[data-tab="investigate"]').click();
      renderReport(full);
    });
  });
  wrap.querySelectorAll(".del-case-btn").forEach((b) => {
    b.addEventListener("click", async () => {
      await fetch(`/api/cases/${encodeURIComponent(b.dataset.cid)}`, { method: "DELETE" });
      loadHistory();
    });
  });
}
document.getElementById("refresh-history-btn").addEventListener("click", loadHistory);
document.getElementById("history-search").addEventListener("input", loadHistory);

/* ---------------- Watchlist Tab ---------------- */
async function loadWatchlist() {
  const res = await fetch("/api/watchlist");
  const data = await res.json();
  const items = data.items || [];
  const wrap = document.getElementById("watchlist-table");
  if (items.length === 0) {
    wrap.innerHTML = `<p class="muted">Watchlist kosong.</p>`;
    return;
  }
  const rows = items
    .map(
      (i) => `
    <tr>
      <td>#${escapeHtml(i.id)}</td>
      <td><code>${escapeHtml(i.indicator)}</code></td>
      <td>${escapeHtml(i.indicator_type)}</td>
      <td><strong>${escapeHtml(i.label)}</strong></td>
      <td>${escapeHtml(i.reason || "-")}</td>
      <td><button type="button" class="btn btn-danger btn-sm del-wl-btn" data-id="${escapeHtml(i.id)}">Hapus</button></td>
    </tr>`
    )
    .join("");
  wrap.innerHTML = `<table><thead><tr><th>ID</th><th>Indikator</th><th>Tipe</th><th>Label</th><th>Alasan</th><th>Aksi</th></tr></thead><tbody>${rows}</tbody></table>`;
  wrap.querySelectorAll(".del-wl-btn").forEach((b) => {
    b.addEventListener("click", async () => {
      await fetch(`/api/watchlist/${encodeURIComponent(b.dataset.id)}`, { method: "DELETE" });
      loadWatchlist();
    });
  });
}

document.getElementById("watchlist-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const indicator = document.getElementById("wl-indicator").value.trim();
  const label = document.getElementById("wl-label").value.trim();
  const reason = document.getElementById("wl-reason").value.trim();
  if (!indicator) return;
  await fetch("/api/watchlist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ indicator, label, reason }),
  });
  document.getElementById("wl-indicator").value = "";
  document.getElementById("wl-reason").value = "";
  loadWatchlist();
});

/* ---------------- Modules Tab ---------------- */
async function loadModules() {
  const res = await fetch("/api/modules");
  const data = await res.json();
  const keys = data.api_keys || {};
  document.getElementById("api-keys-grid").innerHTML = Object.entries(keys)
    .map(
      ([k, on]) =>
        `<span class="key-badge ${on ? "key-on" : "key-off"}">${escapeHtml(k)}: ${on ? "CONFIGURED" : "NOT SET (Optional)"}</span>`
    )
    .join("");

  document.getElementById("modules-catalog-grid").innerHTML = (data.modules || [])
    .map(
      (m) => `
    <div class="mod-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
        <strong>${escapeHtml(m.display_name)}</strong>
        <span class="sev ${m.is_slow ? "sev-medium" : "sev-low"}">${m.is_slow ? "DEEP" : "FAST"}</span>
      </div>
      <div class="muted"><code>${escapeHtml(m.name)}</code> &bull; ${escapeHtml(m.key_status)}</div>
      <p class="muted" style="margin-top:6px;">${escapeHtml(m.description)}</p>
      <div class="muted" style="margin-top:6px;">Target: ${escapeHtml((m.supported_targets || []).join(", "))}</div>
    </div>`
    )
    .join("");
}

/* ---------------- Chat / IOC Extractor Tab ---------------- */
document.getElementById("sample-scam-text-btn").addEventListener("click", () => {
  document.getElementById("scam-text-input").value =
    "Selamat Anda terpilih mendapatkan DANA Kaget! Segera verifikasi melalui http://hadiah-dana-resmi.xyz/login atau install undangan.apk. Untuk biaya admin transfer ke rekening BCA 1234567890 dan konfirmasi WA 081234567890 atau Telegram @admin_dana_resmi.";
});

document.getElementById("text-analyzer-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = document.getElementById("scam-text-input").value.trim();
  if (!text) return;
  const res = await fetch("/api/analyze-text", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error || "Gagal menganalisis teks");
    return;
  }

  document.getElementById("text-analysis-result").classList.remove("hidden");
  const badge = document.getElementById("text-risk-badge");
  badge.textContent = `${data.scam_score}/100 (${data.risk_level})`;
  badge.style.background = riskColor(data.risk_level);

  const modiWrap = document.getElementById("text-modi-list");
  if ((data.matched_modi || []).length === 0) {
    modiWrap.innerHTML = `<p class="muted">Tidak ada pola modus penipuan eksplisit terdeteksi.</p>`;
  } else {
    modiWrap.innerHTML = data.matched_modi
      .map(
        (m) => `
      <div class="signal-item">
        <div>
          <div><span class="sev sev-${escapeHtml(m.severity)}">${escapeHtml(m.severity.toUpperCase())}</span> <strong>${escapeHtml(m.name)}</strong></div>
          <div class="muted">Kata kunci: ${escapeHtml((m.matched_keywords || []).join(", "))}</div>
        </div>
        <div class="signal-pts">+${escapeHtml(m.points)}</div>
      </div>`
      )
      .join("");
  }

  document.getElementById("text-advice-list").innerHTML =
    "<ul>" + (data.recommendations || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("") + "</ul>";

  const iocs = data.iocs || [];
  document.getElementById("text-ioc-count").textContent = String(iocs.length);
  const iocWrap = document.getElementById("text-iocs-list");
  if (iocs.length === 0) {
    iocWrap.innerHTML = `<p class="muted">Tidak ada IOC terdeteksi.</p>`;
  } else {
    iocWrap.innerHTML = iocs
      .map(
        (item, idx) => `
      <div class="pivot-item">
        <div>
          <span class="pivot-type">${escapeHtml(item.type)}</span>
          <strong>${escapeHtml(item.value)}</strong>
          <div class="muted">${escapeHtml(item.label)}</div>
        </div>
        ${
          item.type === "artifact"
            ? `<span class="sev sev-critical">DANGER</span>`
            : `<button type="button" class="btn btn-primary btn-sm text-ioc-scan-btn" data-idx="${idx}">Scan IOC</button>`
        }
      </div>`
      )
      .join("");
    iocWrap.querySelectorAll(".text-ioc-scan-btn").forEach((b) => {
      b.addEventListener("click", () => {
        const item = iocs[Number(b.dataset.idx)];
        if (!item) return;
        document.querySelector('.tab-btn[data-tab="investigate"]').click();
        queryInput.value = item.value;
        const mappedType =
          item.type === "crypto_wallet"
            ? "crypto"
            : item.type === "bank_account"
            ? "bank"
            : item.type;
        typeSelect.value = mappedType;
        updateDetectPreview();
        runScan(item.value, mappedType);
      });
    });
  }
});
