const eventsBody = document.getElementById("events-body");
const detail = document.getElementById("event-detail");
const prompts = document.getElementById("pending-prompts");
const refreshButton = document.getElementById("refresh-button");
const decisionFilter = document.getElementById("decision-filter");
const directionFilter = document.getElementById("direction-filter");
const serverFilter = document.getElementById("server-filter");
const toolFilter = document.getElementById("tool-filter");
const sessionFilter = document.getElementById("session-filter");
const agentFilter = document.getElementById("agent-filter");
const subagentFilter = document.getElementById("subagent-filter");
const chainFilter = document.getElementById("chain-filter");
const driftFilter = document.getElementById("drift-filter");
const searchFilter = document.getElementById("search-filter");
const exportIncidentButton = document.getElementById("export-incident-button");

let currentEvents = [];
let activeIndex = -1;

function decisionBadge(decision) {
  return `<span class="decision decision-${decision}">${decision}</span>`;
}

function actorLabel(event) {
  if (event.subagent_id) return `subagent:${event.subagent_id}`;
  if (event.agent_id) return `parent:${event.agent_id}`;
  return "unknown";
}

function chainSummary(event) {
  const alerts = event.chain_alerts || [];
  if (event.chain_id) return event.chain_id;
  if (!alerts.length) return "";
  return alerts.map((alert) => alert.chain_id).join(", ");
}

function queryString() {
  const params = new URLSearchParams();
  if (decisionFilter.value) params.set("decision", decisionFilter.value);
  if (directionFilter.value) params.set("direction", directionFilter.value);
  if (serverFilter.value) params.set("server_id", serverFilter.value);
  if (toolFilter.value) params.set("tool_name", toolFilter.value);
  if (sessionFilter.value) params.set("session_id", sessionFilter.value);
  if (agentFilter.value) params.set("agent_id", agentFilter.value);
  if (subagentFilter.value) params.set("subagent_id", subagentFilter.value);
  if (chainFilter.value) params.set("chain_id", chainFilter.value);
  if (driftFilter.value) params.set("drift_id", driftFilter.value);
  if (searchFilter.value) params.set("q", searchFilter.value);
  return params.toString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderList(title, values) {
  if (!values || !values.length) return "";
  return `
    <section class="detail-section">
      <h3>${escapeHtml(title)}</h3>
      <ul class="pill-list">
        ${values.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}
      </ul>
    </section>
  `;
}

function renderDiff(diff) {
  if (!diff) return "";
  if (!diff.changes?.length && !("baseline" in diff || "current" in diff)) return "";
  const cards =
    diff.changes?.length
      ? diff.changes
          .map(
            (change) => `
              <article class="diff-card">
                <strong>${escapeHtml(change.field || "change")}</strong>
                <p>${escapeHtml(change.summary || "")}</p>
                <div class="diff-grid">
                  <div>
                    <span class="diff-label">Before</span>
                    <pre>${escapeHtml(JSON.stringify(change.before, null, 2))}</pre>
                  </div>
                  <div>
                    <span class="diff-label">After</span>
                    <pre>${escapeHtml(JSON.stringify(change.after, null, 2))}</pre>
                  </div>
                </div>
              </article>
            `
          )
          .join("")
      : `
        <article class="diff-card">
          <strong>${escapeHtml(diff.kind || "drift")}</strong>
          <div class="diff-grid">
            <div>
              <span class="diff-label">Baseline</span>
              <pre>${escapeHtml(JSON.stringify(diff.baseline, null, 2))}</pre>
            </div>
            <div>
              <span class="diff-label">Current</span>
              <pre>${escapeHtml(JSON.stringify(diff.current, null, 2))}</pre>
            </div>
          </div>
        </article>
      `;
  return `
    <section class="detail-section">
      <h3>Identity Drift</h3>
      <div class="diff-summary">${escapeHtml(diff.summary || "")}</div>
      <div class="diff-list">${cards}</div>
    </section>
  `;
}

function renderEvidence(items) {
  if (!items || !items.length) return "";
  return `
    <section class="detail-section">
      <h3>Evidence</h3>
      <div class="evidence-list">
        ${items
          .map(
            (item) => `
              <article class="evidence-card">
                <pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre>
              </article>
            `
          )
          .join("")}
      </div>
    </section>
  `;
}

function renderHits(hits) {
  if (!hits || !hits.length) return "";
  return `
    <section class="detail-section">
      <h3>Matched Rules</h3>
      <div class="evidence-list">
        ${hits
          .map(
            (hit) => `
              <article class="evidence-card">
                <strong>${escapeHtml(hit.module || hit.name || "rule")}</strong>
                <p>${escapeHtml(hit.output || hit.metadata?.reason || "")}</p>
                <div class="prompt-meta">Confidence ${Math.round((hit.confidence || 0) * 100)}%</div>
              </article>
            `
          )
          .join("")}
      </div>
    </section>
  `;
}

function renderEventDetail(event) {
  if (!event) {
    exportIncidentButton.disabled = true;
    detail.className = "detail empty-state";
    detail.innerHTML = "Select an event to inspect it.";
    return;
  }
  exportIncidentButton.disabled = !event.event_id;
  detail.className = "detail";
  detail.innerHTML = `
    <section class="detail-section detail-hero">
      <div class="detail-kicker">${decisionBadge(event.decision || "allow")} <span>${escapeHtml(event.direction || "runtime")}</span></div>
      <h3>${escapeHtml(event.reason || "Gateway decision")}</h3>
      <p>${escapeHtml(event.safer_alternative || "Review the event evidence before retrying the action.")}</p>
      <div class="detail-metrics">
        <div><span>Runtime</span><strong>${escapeHtml(event.runtime || "gateway")}</strong></div>
        <div><span>Server</span><strong>${escapeHtml(event.server_id || "local")}</strong></div>
        <div><span>Tool</span><strong>${escapeHtml(event.tool_name || event.module || "-")}</strong></div>
        <div><span>Confidence</span><strong>${Math.round((event.confidence || 0) * 100)}%</strong></div>
      </div>
    </section>
    <section class="detail-section">
      <h3>Forensics</h3>
      <dl class="detail-grid">
        <div><dt>Event ID</dt><dd>${escapeHtml(event.event_id || "-")}</dd></div>
        <div><dt>Actor</dt><dd>${escapeHtml(actorLabel(event))}</dd></div>
        <div><dt>Chain Ref</dt><dd>${escapeHtml(event.call_chain_ref || chainSummary(event) || "-")}</dd></div>
        <div><dt>Artifact</dt><dd>${escapeHtml(event.artifact_touched || "-")}</dd></div>
        <div><dt>Drift</dt><dd>${escapeHtml(event.drift_kind || event.drift_id || "-")}</dd></div>
        <div><dt>Latency</dt><dd>${escapeHtml(event.latency_ms ?? "-")}</dd></div>
        <div><dt>Prompt</dt><dd>${escapeHtml(event.prompt_id || "-")}</dd></div>
      </dl>
    </section>
    ${renderList("Matched Signatures", event.signature_modules || [])}
    ${renderHits(event.hits || [])}
    ${renderList("Artifacts Touched", event.artifacts_touched || [])}
    ${event.request_preview_masked ? `<section class="detail-section"><h3>Masked Request Preview</h3><pre>${escapeHtml(event.request_preview_masked)}</pre></section>` : ""}
    ${event.response_preview_masked ? `<section class="detail-section"><h3>Masked Response Preview</h3><pre>${escapeHtml(event.response_preview_masked)}</pre></section>` : ""}
    ${renderDiff(event.diff)}
    ${renderEvidence(event.evidence || [])}
  `;
}

function selectEvent(index) {
  activeIndex = index;
  renderEvents();
  const event = currentEvents[index];
  renderEventDetail(event);
}

function renderEvents() {
  if (!currentEvents.length) {
    eventsBody.innerHTML = `<tr><td colspan="7" class="empty-state">No events match the current filters.</td></tr>`;
    renderEventDetail(null);
    return;
  }
  eventsBody.innerHTML = currentEvents
    .slice()
    .reverse()
    .map((event, idx) => {
      const actualIndex = currentEvents.length - 1 - idx;
      const rowClass = actualIndex === activeIndex ? "active" : "";
      return `
        <tr data-index="${actualIndex}" class="${rowClass}">
          <td>${new Date(event.ts).toLocaleTimeString()}</td>
          <td>${decisionBadge(event.decision)}</td>
          <td>${actorLabel(event)}</td>
          <td>${event.direction || "runtime"}</td>
          <td>${event.server_id || "local"}</td>
          <td>${event.tool_name || event.module || "-"}</td>
          <td>${chainSummary(event) ? `${event.reason || "-"} [${chainSummary(event)}]` : event.reason || "-"}</td>
        </tr>
      `;
    })
    .join("");

  [...eventsBody.querySelectorAll("tr[data-index]")].forEach((row) => {
    row.addEventListener("click", () => selectEvent(Number(row.dataset.index)));
  });
}

function renderPrompts(items) {
  if (!items.length) {
    prompts.className = "stack empty-state";
    prompts.textContent = "No pending prompts.";
    return;
  }
  prompts.className = "stack";
  prompts.innerHTML = items
    .map(
      (item) => `
        <article class="prompt-card">
          <header>
            <strong>${item.server_id}__${item.tool_name}</strong>
            ${decisionBadge("prompt")}
          </header>
          <div class="prompt-meta">${item.direction || "request"} checkpoint · ${actorLabel(item)}</div>
          <div>${item.hits?.[0]?.output || "Review required for this request."}</div>
          ${chainSummary(item) ? `<div class="prompt-meta">Chains: ${chainSummary(item)}</div>` : ""}
          ${item.response_hint ? `<pre class="prompt-preview">${item.response_hint}</pre>` : ""}
          <div class="prompt-actions">
            <button type="button" data-action="approve" data-id="${item.id}">Approve</button>
            <button type="button" data-action="deny" data-id="${item.id}">Deny</button>
          </div>
        </article>
      `
    )
    .join("");

  [...prompts.querySelectorAll("button[data-id]")].forEach((button) => {
    button.addEventListener("click", async () => {
      await fetch(`/api/pending-prompts/${button.dataset.id}/${button.dataset.action}`, {
        method: "POST",
      });
      await Promise.all([loadEvents(), loadPrompts()]);
    });
  });
}

async function loadHealth() {
  const response = await fetch("/health");
  const payload = await response.json();
  document.getElementById("health-status").textContent = payload.ok ? "Healthy" : "Degraded";
  document.getElementById("health-profile").textContent = payload.profile;
  document.getElementById("health-servers").textContent = payload.servers.length;
}

async function loadEvents() {
  const response = await fetch(`/api/events?${queryString()}`);
  const payload = await response.json();
  currentEvents = payload.events || [];
  if (activeIndex >= currentEvents.length) activeIndex = -1;
  renderEvents();
  renderEventDetail(currentEvents[activeIndex] || null);
}

async function loadPrompts() {
  const response = await fetch("/api/pending-prompts");
  const payload = await response.json();
  renderPrompts(payload.pending || []);
}

function connectStream() {
  const stream = new EventSource("/api/events/stream");
  stream.onmessage = async () => {
    await loadEvents();
    await loadPrompts();
  };
}

refreshButton.addEventListener("click", async () => {
  await Promise.all([loadHealth(), loadEvents(), loadPrompts()]);
});

exportIncidentButton.addEventListener("click", async () => {
  const event = currentEvents[activeIndex];
  if (!event?.event_id) return;
  const response = await fetch("/api/incidents/export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ selector: `event:${event.event_id}`, format: "json" }),
  });
  const payload = await response.json();
  const blob = new Blob([JSON.stringify(payload.bundle || payload, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `runwall-incident-${event.event_id}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

[decisionFilter, directionFilter, serverFilter, toolFilter, sessionFilter, agentFilter, subagentFilter, chainFilter, driftFilter, searchFilter].forEach((element) =>
  element.addEventListener("change", loadEvents)
);

searchFilter.addEventListener("input", loadEvents);

Promise.all([loadHealth(), loadEvents(), loadPrompts()]);
connectStream();
