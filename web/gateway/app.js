const eventsBody = document.getElementById("events-body");
const detail = document.getElementById("event-detail");
const prompts = document.getElementById("pending-prompts");
const refreshButton = document.getElementById("refresh-button");
const decisionFilter = document.getElementById("decision-filter");
const serverFilter = document.getElementById("server-filter");
const toolFilter = document.getElementById("tool-filter");

let currentEvents = [];
let activeIndex = -1;

function decisionBadge(decision) {
  return `<span class="decision decision-${decision}">${decision}</span>`;
}

function queryString() {
  const params = new URLSearchParams();
  if (decisionFilter.value) params.set("decision", decisionFilter.value);
  if (serverFilter.value) params.set("server_id", serverFilter.value);
  if (toolFilter.value) params.set("tool_name", toolFilter.value);
  return params.toString();
}

function selectEvent(index) {
  activeIndex = index;
  renderEvents();
  const event = currentEvents[index];
  detail.textContent = event ? JSON.stringify(event, null, 2) : "Select an event to inspect it.";
}

function renderEvents() {
  if (!currentEvents.length) {
    eventsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No events match the current filters.</td></tr>`;
    detail.textContent = "Select an event to inspect it.";
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
          <td>${event.server_id || "local"}</td>
          <td>${event.tool_name || event.module || "-"}</td>
          <td>${event.reason || "-"}</td>
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
          <div>${item.hits?.[0]?.output || "Review required for this request."}</div>
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

[decisionFilter, serverFilter, toolFilter].forEach((element) =>
  element.addEventListener("change", loadEvents)
);

Promise.all([loadHealth(), loadEvents(), loadPrompts()]);
connectStream();
