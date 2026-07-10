const DATA_FILES = {
  ip: "data/ip.json",
  domain: "data/domain.json",
  url: "data/url.json",
  hash: "data/hash.json",
  email: "data/email.json",
  cve: "data/cve.json",
  incidents: "data/incidents.json",
};

const state = {
  data: {},
  charts: [],
  activeIncident: null,
  activeIOC: null,
  feedRows: [],
  feedSort: "date-desc",
  workflowTimer: null,
};

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const severityOrder = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Safe: 0,
};

function pick(list, fallback = null) {
  if (!list || !list.length) return fallback;
  return list[Math.floor(Math.random() * list.length)];
}

function pad2(value) {
  return String(value).padStart(2, "0");
}

function formatDateTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(date);
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

async function fetchJSON(path) {
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to load ${path}`);
    }
    return await response.json();
  } catch (error) {
    console.error(error);
    return [];
  }
}

function normalize(value) {
  return String(value ?? "").trim().toLowerCase();
}

function severityClass(severity) {
  const value = normalize(severity);
  if (value.includes("critical")) return "red";
  if (value.includes("high")) return "orange";
  if (value.includes("medium")) return "yellow";
  if (value.includes("low")) return "green";
  return "neutral";
}

function riskClass(riskLevel) {
  const value = normalize(riskLevel);
  if (value.includes("critical") || value === "red") return "red";
  if (value.includes("high") || value === "orange") return "orange";
  if (value.includes("medium") || value === "yellow") return "yellow";
  if (value.includes("safe") || value === "green" || value.includes("low")) return "green";
  return "neutral";
}

function destroyCharts() {
  state.charts.forEach((chart) => chart.destroy());
  state.charts = [];
}

function sumBy(list, selector) {
  return list.reduce((total, item) => total + Number(selector(item) || 0), 0);
}

function countBy(list, selector) {
  return list.reduce((accumulator, item) => {
    const key = selector(item) || "Unknown";
    accumulator[key] = (accumulator[key] || 0) + 1;
    return accumulator;
  }, {});
}

function latestDate(values) {
  const parsed = values
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()))
    .sort((left, right) => right - left);
  return parsed[0] ? parsed[0].toISOString() : null;
}

function getAnalystName() {
  return "A. Mehta, SOC Analyst";
}

function getCombinedIndicatorCount() {
  return ["ip", "domain", "url", "hash", "email"].reduce((total, key) => total + (state.data[key]?.length || 0), 0);
}

function buildMetricCard(title, value, detail, icon) {
  return `
    <article class="metric reveal">
      <div class="icon">${icon}</div>
      <div class="label">${title}</div>
      <div class="value">${value}</div>
      <div class="small">${detail}</div>
    </article>
  `;
}

function renderLanding() {
  document.querySelectorAll("[data-nav-target]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.navTarget;
      if (target === "investigation") {
        localStorage.setItem("gcfAutoStart", "1");
        window.location.href = "investigation.html";
      } else if (target === "dashboard") {
        window.location.href = "dashboard.html";
      }
    });
  });

  const learnMore = document.querySelector("[data-scroll-target]");
  if (learnMore) {
    learnMore.addEventListener("click", () => {
      document.querySelector("#platform-features")?.scrollIntoView({ behavior: "smooth" });
    });
  }
}

function buildThreatRows(rows) {
  const tbody = document.querySelector("#feed-body");
  const empty = document.querySelector("#feed-empty");
  if (!tbody) return;

  if (!rows.length) {
    tbody.innerHTML = "";
    if (empty) empty.classList.remove("hidden");
    return;
  }

  if (empty) empty.classList.add("hidden");
  tbody.innerHTML = rows
    .map((row) => {
      return `
        <tr>
          <td>${formatDate(row.date)}</td>
          <td>${row.threat}</td>
          <td><span class="tag neutral">${row.category}</span></td>
          <td>${row.country}</td>
          <td><span class="badge ${severityClass(row.severity)}">${row.severity}</span></td>
          <td>${row.status}</td>
        </tr>
      `;
    })
    .join("");
}

function getThreatFeedRows() {
  const rows = (state.data.incidents || []).map((incident) => ({
    date: incident.date,
    threat: `${incident.alertType} activity`,
    category: incident.category,
    country: incident.country,
    severity: incident.severity,
    status: incident.status,
    searchText: `${incident.alertType} ${incident.employeeName} ${incident.category} ${incident.country} ${incident.status}`,
  }));
  state.feedRows = rows;
  return rows;
}

function applyFeedFilters() {
  const search = normalize(document.querySelector("#feed-search")?.value);
  const severity = document.querySelector("#feed-severity")?.value || "all";
  const country = document.querySelector("#feed-country")?.value || "all";
  const sort = document.querySelector("#feed-sort")?.value || state.feedSort;

  const filtered = getThreatFeedRows().filter((row) => {
    const matchesSearch = !search || normalize(row.searchText).includes(search);
    const matchesSeverity = severity === "all" || normalize(row.severity) === normalize(severity);
    const matchesCountry = country === "all" || normalize(row.country) === normalize(country);
    return matchesSearch && matchesSeverity && matchesCountry;
  });

  filtered.sort((left, right) => {
    if (sort === "severity-desc") {
      return (severityOrder[right.severity] || 0) - (severityOrder[left.severity] || 0);
    }
    return new Date(right.date) - new Date(left.date);
  });

  buildThreatRows(filtered);
}

function renderDashboard() {
  destroyCharts();

  const incidents = state.data.incidents || [];
  const combinedIndicators = getCombinedIndicatorCount();
  const criticalAlerts = incidents.filter((item) => normalize(item.severity).includes("critical")).length;
  const highRiskIndicators = [...(state.data.ip || []), ...(state.data.domain || []), ...(state.data.url || []), ...(state.data.hash || []), ...(state.data.email || [])].filter((item) => normalize(item.riskLevel).includes("high") || normalize(item.riskLevel).includes("critical")).length;
  const mediumRiskIndicators = [...(state.data.ip || []), ...(state.data.domain || []), ...(state.data.url || []), ...(state.data.hash || []), ...(state.data.email || [])].filter((item) => normalize(item.riskLevel).includes("medium")).length;
  const safeIndicators = [...(state.data.ip || []), ...(state.data.domain || []), ...(state.data.url || []), ...(state.data.hash || []), ...(state.data.email || [])].filter((item) => normalize(item.riskLevel).includes("safe") || normalize(item.riskLevel).includes("low")).length;
  const activeIncidents = incidents.filter((item) => !["Closed", "Contained"].includes(item.status)).length;

  const stats = document.querySelector("#dashboard-stats");
  if (stats) {
    stats.innerHTML = [
      buildMetricCard("Total Threats", combinedIndicators + incidents.length, "Across all demo datasets", "01"),
      buildMetricCard("Active Incidents", activeIncidents, "In-progress SOC cases", "02"),
      buildMetricCard("Critical Alerts", criticalAlerts, "Requires immediate review", "03"),
      buildMetricCard("High Risk Indicators", highRiskIndicators, "Indicators flagged as high", "04"),
      buildMetricCard("Medium Risk Indicators", mediumRiskIndicators, "Indicators under watch", "05"),
      buildMetricCard("Safe Indicators", safeIndicators, "Benign or low-risk observations", "06"),
    ].join("");
  }

  const clockEl = document.querySelector("#digital-clock");
  const dateEl = document.querySelector("#current-date");
  const lastUpdateEl = document.querySelector("#last-threat-update");
  const socStatusEl = document.querySelector("#soc-status");
  const analystEl = document.querySelector("#analyst-name");

  const updateTime = () => {
    const now = new Date();
    if (clockEl) clockEl.textContent = `${pad2(now.getHours())}:${pad2(now.getMinutes())}:${pad2(now.getSeconds())}`;
    if (dateEl) dateEl.textContent = new Intl.DateTimeFormat("en-GB", { weekday: "long", day: "2-digit", month: "short", year: "numeric" }).format(now);
  };
  updateTime();
  window.clearInterval(window.__gcfClock);
  window.__gcfClock = window.setInterval(updateTime, 1000);

  const latestThreat = latestDate([...(state.data.incidents || []).map((item) => item.date), ...(state.data.ip || []).map((item) => item.lastSeen), ...(state.data.domain || []).map((item) => item.lastSeen), ...(state.data.url || []).map((item) => item.lastSeen), ...(state.data.hash || []).map((item) => item.lastSeen), ...(state.data.email || []).map((item) => item.lastSeen)]);
  if (lastUpdateEl) lastUpdateEl.textContent = latestThreat ? formatDateTime(latestThreat) : "N/A";
  if (socStatusEl) socStatusEl.textContent = activeIncidents > 6 ? "Elevated Monitoring" : "Operational";
  if (analystEl) analystEl.textContent = getAnalystName();

  const categoryCounts = countBy(incidents, (item) => item.category);
  const severityCounts = countBy(incidents, (item) => item.severity);
  const attackCounts = countBy(incidents, (item) => item.threatType || item.alertType || "Unknown");
  const monthlyCounts = countBy(incidents, (item) => new Date(item.date).toLocaleString("en-US", { month: "short" }));
  const countryCounts = countBy(incidents, (item) => item.country);

  const charts = [
    {
      canvas: "threat-distribution-chart",
      type: "doughnut",
      labels: Object.keys(categoryCounts),
      data: Object.values(categoryCounts),
    },
    {
      canvas: "severity-breakdown-chart",
      type: "bar",
      labels: Object.keys(severityCounts),
      data: Object.values(severityCounts),
    },
    {
      canvas: "attack-categories-chart",
      type: "radar",
      labels: Object.keys(attackCounts),
      data: Object.values(attackCounts),
    },
    {
      canvas: "monthly-incidents-chart",
      type: "line",
      labels: Object.keys(monthlyCounts),
      data: Object.values(monthlyCounts),
    },
    {
      canvas: "country-distribution-chart",
      type: "polarArea",
      labels: Object.keys(countryCounts),
      data: Object.values(countryCounts),
    },
  ];

  charts.forEach((chartConfig) => {
    const canvas = document.getElementById(chartConfig.canvas);
    if (!canvas || typeof Chart === "undefined") return;
    const context = canvas.getContext("2d");
    const gradient = context.createLinearGradient(0, 0, 0, 320);
    gradient.addColorStop(0, "rgba(103, 232, 249, 0.95)");
    gradient.addColorStop(1, "rgba(73, 166, 255, 0.45)");

    const chart = new Chart(context, {
      type: chartConfig.type,
      data: {
        labels: chartConfig.labels,
        datasets: [
          {
            label: chartConfig.canvas,
            data: chartConfig.data,
            backgroundColor: ["rgba(103, 232, 249, 0.88)", "rgba(73, 166, 255, 0.88)", "rgba(53, 211, 157, 0.88)", "rgba(246, 196, 69, 0.88)", "rgba(255, 159, 67, 0.88)", "rgba(255, 107, 120, 0.88)"],
            borderColor: "rgba(103, 232, 249, 0.9)",
            borderWidth: 2,
            fill: chartConfig.type === "line" || chartConfig.type === "radar",
            tension: 0.35,
            pointBackgroundColor: gradient,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(7, 17, 31, 0.96)",
            borderColor: "rgba(103, 232, 249, 0.3)",
            borderWidth: 1,
          },
        },
        scales: chartConfig.type === "doughnut" || chartConfig.type === "polarArea" ? {} : {
          x: { ticks: { color: "#9eb7d6" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: { ticks: { color: "#9eb7d6" }, grid: { color: "rgba(255,255,255,0.05)" } },
        },
      },
    });
    state.charts.push(chart);
  });

  const feedTable = document.querySelector("#feed-body");
  if (feedTable) {
    const countries = [...new Set(incidents.map((item) => item.country))].sort();
    const severities = [...new Set(incidents.map((item) => item.severity))].sort((a, b) => severityOrder[b] - severityOrder[a]);
    const countrySelect = document.querySelector("#feed-country");
    const severitySelect = document.querySelector("#feed-severity");
    if (countrySelect && countrySelect.options.length <= 1) {
      countries.forEach((country) => {
        countrySelect.insertAdjacentHTML("beforeend", `<option value="${country}">${country}</option>`);
      });
    }
    if (severitySelect && severitySelect.options.length <= 1) {
      severities.forEach((severity) => {
        severitySelect.insertAdjacentHTML("beforeend", `<option value="${severity}">${severity}</option>`);
      });
    }
    applyFeedFilters();
    ["#feed-search", "#feed-country", "#feed-severity", "#feed-sort"].forEach((selector) => {
      const element = document.querySelector(selector);
      if (!element) return;
      element.addEventListener("input", applyFeedFilters);
      element.addEventListener("change", applyFeedFilters);
    });
  }

  const cveSearch = document.querySelector("#cve-search");
  const cveBody = document.querySelector("#cve-body");
  const cveEmpty = document.querySelector("#cve-empty");

  const renderCVE = () => {
    if (!cveBody) return;
    const search = normalize(cveSearch?.value);
    const rows = (state.data.cve || []).filter((item) => {
      if (!search) return true;
      return normalize(item.cveId).includes(search) || normalize(item.description).includes(search) || normalize(item.affectedProduct).includes(search) || normalize(item.severity).includes(search);
    });

    if (!rows.length) {
      cveBody.innerHTML = "";
      cveEmpty?.classList.remove("hidden");
      return;
    }

    cveEmpty?.classList.add("hidden");
    cveBody.innerHTML = rows
      .map((item) => {
        return `
          <tr>
            <td>${item.cveId}</td>
            <td>${item.description}</td>
            <td>${item.cvssScore}</td>
            <td><span class="badge ${severityClass(item.severity)}">${item.severity}</span></td>
            <td>${item.affectedProduct}</td>
            <td>${item.mitigation}</td>
          </tr>
        `;
      })
      .join("");
  };

  if (cveSearch) {
    cveSearch.addEventListener("input", renderCVE);
    renderCVE();
  }

  renderThreatMap("#dashboard-map", state.data.incidents || []);
}

function renderThreatMap(targetSelector, incidents) {
  const container = document.querySelector(targetSelector);
  if (!container) return;

  const countries = ["India", "USA", "Germany", "Russia", "United Kingdom", "China"];
  const locations = {
    India: { left: 66, top: 52 },
    USA: { left: 18, top: 40 },
    Germany: { left: 52, top: 33 },
    Russia: { left: 68, top: 25 },
    "United Kingdom": { left: 47, top: 28 },
    China: { left: 73, top: 43 },
  };

  const counts = countBy(incidents, (item) => item.country);
  const total = sumBy(Object.values(counts), (value) => value);

  container.innerHTML = `
    <div class="map-stage">
      <svg viewBox="0 0 1000 500" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <linearGradient id="mapGlow" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="rgba(103, 232, 249, 0.8)" />
            <stop offset="100%" stop-color="rgba(73, 166, 255, 0.35)" />
          </linearGradient>
        </defs>
        <ellipse cx="500" cy="250" rx="420" ry="180" fill="rgba(255,255,255,0.03)" stroke="rgba(103, 232, 249, 0.18)" stroke-width="2" />
        <path d="M140,230 C250,120 390,110 510,165 C620,216 730,140 850,210" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="2" />
        <path d="M120,290 C260,220 380,210 520,280 C650,340 760,310 880,250" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="2" />
        <path d="M220,95 C270,180 300,250 310,395" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="2" />
        <path d="M390,70 C415,160 420,245 410,440" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="2" />
        <path d="M620,80 C590,170 585,250 595,430" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="2" />
        <path d="M780,85 C745,180 735,255 740,390" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="2" />
      </svg>
    </div>
    <div class="meta-row" style="margin-top:14px;">
      <span class="badge neutral">Global activity: ${total} incidents</span>
      ${countries.map((country) => `<span class="badge ${severityClass(counts[country] > 5 ? "High" : counts[country] > 2 ? "Medium" : "Low")}">${country}: ${counts[country] || 0}</span>`).join("")}
    </div>
  `;

  const mapStage = container.querySelector(".map-stage");
  if (!mapStage) return;

  const attackPairs = [
    ["USA", "India"],
    ["Germany", "United Kingdom"],
    ["Russia", "China"],
    ["India", "Germany"],
    ["China", "USA"],
  ];

  countries.forEach((country, index) => {
    const point = document.createElement("div");
    point.className = "map-node";
    point.dataset.label = `${country}`;
    point.style.left = `${locations[country].left}%`;
    point.style.top = `${locations[country].top}%`;
    point.style.animationDelay = `${index * 0.3}s`;
    mapStage.appendChild(point);
  });

  attackPairs.forEach(([from, to], index) => {
    const start = locations[from];
    const end = locations[to];
    const line = document.createElement("div");
    line.className = "attack-line";
    const deltaX = end.left - start.left;
    const deltaY = end.top - start.top;
    const length = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
    const angle = Math.atan2(deltaY, deltaX) * (180 / Math.PI);
    line.style.left = `${start.left}%`;
    line.style.top = `${start.top}%`;
    line.style.width = `${length}%`;
    line.style.transform = `rotate(${angle}deg)`;
    line.style.animationDelay = `${index * 0.5}s`;
    mapStage.appendChild(line);
  });
}

function pickIncident() {
  return pick(state.data.incidents, null);
}

function renderWorkflow(steps, activeIndex = 0) {
  const workflow = document.querySelector("#workflow-steps");
  if (!workflow) return;
  workflow.innerHTML = steps
    .map((step, index) => `
      <div class="workflow-step ${index <= activeIndex ? "active" : ""}" data-step-index="${index}">
        <span class="bullet"></span>
        <div>
          <strong>${step.title}</strong>
          <small>${step.detail}</small>
        </div>
      </div>
    `)
    .join("");
}

function renderSummary(incident, match) {
  const summary = document.querySelector("#ai-summary");
  if (!summary) return;

  const indicatorLabel = match ? match.label : incident.alertType;
  summary.innerHTML = `
    <div class="metric-grid">
      <article class="metric reveal">
        <div class="icon">AI</div>
        <div class="label">Threat Classification</div>
        <div class="value">${incident.category}</div>
        <div class="small">Alert source: ${incident.alertType}</div>
      </article>
      <article class="metric reveal">
        <div class="icon">SR</div>
        <div class="label">Severity</div>
        <div class="value">${incident.severity}</div>
        <div class="small">Priority ${incident.priority}</div>
      </article>
      <article class="metric reveal">
        <div class="icon">CF</div>
        <div class="label">Confidence Score</div>
        <div class="value">${incident.confidence}%</div>
        <div class="small">Evidence-backed assessment</div>
      </article>
    </div>
    <div class="layout-grid" style="margin-top:18px;">
      <div class="panel">
        <h4>MITRE ATT&CK Stage</h4>
        <div class="tag neutral">${incident.mitreStage}</div>
        <p class="small" style="margin-top:12px;">Visualization only for academic review. No offensive operations are performed.</p>
      </div>
      <div class="panel">
        <h4>Evidence Found</h4>
        <p>${incident.evidence}</p>
      </div>
    </div>
    <div class="layout-grid" style="margin-top:18px;">
      <div class="panel">
        <h4>Indicators Identified</h4>
        <p>${indicatorLabel}</p>
        <div class="meta" style="margin-top:10px;">Country: ${incident.country}</div>
      </div>
      <div class="panel">
        <h4>Recommended Actions</h4>
        <p>${incident.recommendation}</p>
      </div>
    </div>
  `;
}

function getLookupDataset(type) {
  return state.data[type] || [];
}

function findLookupResult(type, query) {
  const dataset = getLookupDataset(type);
  const normalizedQuery = normalize(query);
  return dataset.find((item) => {
    const values = Object.values(item).map((entry) => normalize(entry));
    return values.some((value) => value.includes(normalizedQuery));
  }) || null;
}

function renderLookupResult(result, type, query) {
  const container = document.querySelector("#lookup-result");
  const meter = document.querySelector("#risk-meter");
  const label = document.querySelector("#lookup-label");
  if (!container) return;

  if (!result) {
    container.innerHTML = `
      <div class="notice">No local demo match found for ${query}. Try another ${type.toUpperCase()} indicator.</div>
    `;
    if (meter) meter.style.width = "18%";
    if (label) label.textContent = "Green";
    return;
  }

  const risk = normalize(result.riskLevel);
  const confidence = Number(result.confidence || 0);
  const meterWidth = clamp(confidence, 20, 96);
  if (meter) meter.style.width = `${meterWidth}%`;
  if (label) label.textContent = result.riskLevel;

  container.innerHTML = `
    <div class="kv-grid">
      <div class="kv"><span>Indicator</span><strong>${result[type] || result.indicator || query}</strong></div>
      <div class="kv"><span>Country</span><strong>${result.country || "Unknown"}</strong></div>
      <div class="kv"><span>Threat Category</span><strong>${result.threatCategory || result.category || "Unknown"}</strong></div>
      <div class="kv"><span>Risk Level</span><strong><span class="risk-chip ${riskClass(result.riskLevel)}">${result.riskLevel || "Unknown"}</span></strong></div>
      <div class="kv"><span>Confidence</span><strong>${result.confidence || "N/A"}%</strong></div>
      <div class="kv"><span>First Seen</span><strong>${formatDateTime(result.firstSeen)}</strong></div>
      <div class="kv"><span>Last Seen</span><strong>${formatDateTime(result.lastSeen)}</strong></div>
      <div class="kv"><span>Recommended Action</span><strong>${result.recommendedAction || result.mitigation || "Review and monitor"}</strong></div>
    </div>
    <div class="panel" style="margin-top:16px;">
      <h4>Threat Description</h4>
      <p>${result.description || result.summary || "No description available."}</p>
    </div>
  `;
}

function revealInvestigationDetails() {
  const details = document.querySelector("#investigation-details");
  if (details) {
    details.classList.remove("hidden");
  }
}

function findIncidentForLookup(type, query) {
  const normalizedQuery = normalize(query);
  return (state.data.incidents || []).find((incident) => {
    const values = [
      incident.indicatorValue,
      incident.alertType,
      incident.employeeName,
      incident.category,
      incident.country,
      incident.severity,
      incident.status,
      incident.priority,
      incident.incidentId,
    ].map((value) => normalize(value));

    const lookupMatch = values.some((value) => value.includes(normalizedQuery));
    if (lookupMatch) return true;

    const typeValue = normalize(incident.indicatorType);
    if (typeValue !== normalize(type)) return false;
    return normalize(incident.indicatorValue).includes(normalizedQuery);
  }) || null;
}

function renderIncidentCard(incident) {
  const card = document.querySelector("#incident-card");
  if (!card) return;
  card.innerHTML = `
    <div class="stat-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
      <article class="stat-card">
        <div class="label">Incident ID</div>
        <div class="value">${incident.incidentId}</div>
      </article>
      <article class="stat-card">
        <div class="label">Employee Name</div>
        <div class="value">${incident.employeeName}</div>
      </article>
      <article class="stat-card">
        <div class="label">Alert Type</div>
        <div class="value">${incident.alertType}</div>
      </article>
      <article class="stat-card">
        <div class="label">Status</div>
        <div class="value">${incident.status}</div>
      </article>
    </div>
    <div class="meta-row" style="margin-top:14px;">
      <span class="badge ${severityClass(incident.severity)}">Priority ${incident.priority}</span>
      <span class="badge neutral">${incident.country}</span>
      <span class="badge neutral">${incident.category}</span>
      <span class="badge neutral">Confidence ${incident.confidence}%</span>
    </div>
  `;
}

function renderIncidentTimeline(incident) {
  const timeline = document.querySelector("#incident-timeline");
  if (!timeline) return;

  const events = incident.timeline || [
    { time: "08:55", title: "Alert Received", detail: "Initial detection from local demo feed" },
    { time: "09:00", title: "Threat Detected", detail: "Indicators cross-referenced across datasets" },
    { time: "09:03", title: "IOC Investigation", detail: "Infrastructure and artifact review" },
    { time: "09:06", title: "Threat Confirmed", detail: "Analyst review confirms malicious intent" },
    { time: "09:08", title: "Containment", detail: "Simulated containment action recorded" },
    { time: "09:10", title: "Report Generated", detail: "Case package prepared for presentation" },
  ];

  timeline.innerHTML = events
    .map((event, index) => `
      <div class="timeline-step ${index === events.length - 1 ? "active" : ""}">
        <div class="time">${event.time}</div>
        <span class="bullet"></span>
        <div>
          <strong>${event.title}</strong>
          <small>${event.detail}</small>
        </div>
      </div>
    `)
    .join("");
}

function updateReport(incident, lookupMatch) {
  const fields = {
    reportIncidentId: incident.incidentId,
    reportTitle: incident.alertType,
    reportSummary: incident.summary,
    reportEvidence: incident.evidence,
    reportIndicators: lookupMatch ? `${lookupMatch.indicator || lookupMatch.ip || lookupMatch.domain || lookupMatch.url || lookupMatch.hash || lookupMatch.email} | ${lookupMatch.threatCategory || lookupMatch.category || incident.category}` : incident.alertType,
    reportRisk: `${incident.riskScore}/100`,
    reportRecommendations: incident.recommendation,
    reportNotes: incident.analystNotes,
    reportDate: formatDateTime(incident.date),
    reportThreatClass: incident.category,
    reportSeverity: incident.severity,
  };

  Object.entries(fields).forEach(([id, value]) => {
    const element = document.querySelector(`#${id}`);
    if (element) element.textContent = value;
  });
}

function renderInvestigation() {
  const incident = state.activeIncident || pickIncident();
  if (!incident) return;

  state.activeIncident = incident;
  localStorage.setItem("gcfCurrentIncident", JSON.stringify(incident));
  revealInvestigationDetails();
  renderIncidentCard(incident);
  renderWorkflow([
    { title: "Alert Generated", detail: "SOC alert created from safe local demo data" },
    { title: "Indicators Collected", detail: "Correlated logs, URLs, hashes, and emails" },
    { title: "Threat Intelligence Analysis", detail: "Compared against local threat records" },
    { title: "Risk Assessment", detail: "Assigned risk level and confidence score" },
    { title: "AI Investigation Summary", detail: "Generated academic SOC summary" },
    { title: "Incident Report", detail: "Prepared printable case material" },
    { title: "Case Closed", detail: "Case closed for classroom demonstration" },
  ], 0);
  renderIncidentTimeline(incident);
  renderSummary(incident, null);
  updateReport(incident, null);

  const steps = document.querySelectorAll("#workflow-steps .workflow-step");
  steps.forEach((step, index) => {
    step.style.opacity = "0";
    step.style.transform = "translateY(12px)";
    setTimeout(() => {
      step.style.opacity = "1";
      step.style.transform = "translateY(0)";
      step.classList.add("active");
    }, 360 * index);
  });
}

function startSimulation() {
  if (state.workflowTimer) {
    clearInterval(state.workflowTimer);
  }

  const incident = pickIncident();
  if (!incident) return;

  state.activeIncident = incident;
  localStorage.setItem("gcfCurrentIncident", JSON.stringify(incident));
  revealInvestigationDetails();

  const workflowSteps = [
    { title: "Alert Generated", detail: "SOC alert created from safe local demo data" },
    { title: "Indicators Collected", detail: "Correlated logs, URLs, hashes, and emails" },
    { title: "Threat Intelligence Analysis", detail: "Compared against local threat records" },
    { title: "Risk Assessment", detail: "Assigned risk level and confidence score" },
    { title: "AI Investigation Summary", detail: "Generated academic SOC summary" },
    { title: "Incident Report", detail: "Prepared printable case material" },
    { title: "Case Closed", detail: "Case closed for classroom demonstration" },
  ];

  renderIncidentCard(incident);
  renderIncidentTimeline(incident);
  renderWorkflow(workflowSteps, 0);

  const summaryTarget = document.querySelector("#ai-summary");
  if (summaryTarget) summaryTarget.innerHTML = `<div class="notice">Running investigation workflow...</div>`;

  let activeStep = 0;
  const steps = document.querySelectorAll("#workflow-steps .workflow-step");
  steps.forEach((step) => step.classList.remove("active"));

  const match = findBestLookupMatch(incident);
  state.activeIOC = match;

  const runStep = () => {
    steps.forEach((step, index) => {
      step.classList.toggle("active", index <= activeStep);
    });
    renderSummary(incident, match);
    updateReport(incident, match);
    activeStep += 1;
    if (activeStep >= workflowSteps.length) {
      clearInterval(state.workflowTimer);
      state.workflowTimer = null;
      steps.forEach((step) => step.classList.add("active"));
    }
  };

  runStep();
  state.workflowTimer = setInterval(runStep, 900);
}

function findBestLookupMatch(incident) {
  const query = incident.indicatorValue || incident.indicator || incident.alertType || "";
  const lookups = [
    ["ip", state.data.ip],
    ["domain", state.data.domain],
    ["url", state.data.url],
    ["hash", state.data.hash],
    ["email", state.data.email],
  ];

  for (const [type, dataset] of lookups) {
    const found = (dataset || []).find((item) => {
      const value = item[type] || item.indicator || item.domain || item.url || item.hash || item.email || item.ip || "";
      return normalize(value).includes(normalize(query)) || normalize(item.threatCategory).includes(normalize(incident.category));
    });
    if (found) return { ...found, type, label: found[type] || found.indicator || query };
  }

  return null;
}

function initInvestigation() {
  const autoStart = localStorage.getItem("gcfAutoStart") === "1";
  if (autoStart) {
    localStorage.removeItem("gcfAutoStart");
  }

  const storedIncident = localStorage.getItem("gcfCurrentIncident");
  if (storedIncident) {
    try {
      state.activeIncident = JSON.parse(storedIncident);
    } catch {
      state.activeIncident = null;
    }
  }

  const startButton = document.querySelector("#start-investigation");
  if (startButton) {
    startButton.addEventListener("click", startSimulation);
  }

  const lookupForm = document.querySelector("#lookup-form");
  if (lookupForm) {
    lookupForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const type = document.querySelector("#lookup-type")?.value || "ip";
      const query = document.querySelector("#lookup-query")?.value || "";
      const result = findLookupResult(type, query);
      state.activeIOC = result;
      renderLookupResult(result, type, query);

      const matchedIncident = findIncidentForLookup(type, query) || state.activeIncident || pickIncident();
      if (matchedIncident) {
        state.activeIncident = matchedIncident;
        localStorage.setItem("gcfCurrentIncident", JSON.stringify(matchedIncident));
        revealInvestigationDetails();
        renderIncidentCard(matchedIncident);
        renderWorkflow([
          { title: "Alert Generated", detail: "SOC alert created from safe local demo data" },
          { title: "Indicators Collected", detail: "Correlated logs, URLs, hashes, and emails" },
          { title: "Threat Intelligence Analysis", detail: "Compared against local threat records" },
          { title: "Risk Assessment", detail: "Assigned risk level and confidence score" },
          { title: "AI Investigation Summary", detail: "Generated academic SOC summary" },
          { title: "Incident Report", detail: "Prepared printable case material" },
          { title: "Case Closed", detail: "Case closed for classroom demonstration" },
        ], 0);
        renderIncidentTimeline(matchedIncident);
        renderSummary(matchedIncident, result);
        updateReport(matchedIncident, result);
      }
    });
  }

  if (autoStart) {
    startSimulation();
  }

  renderThreatMap("#investigation-map", state.data.incidents || []);
}

function initReports() {
  const incident = state.activeIncident || pickIncident();
  if (!incident) return;

  const match = state.activeIOC || findBestLookupMatch(incident);
  updateReport(incident, match);
  renderIncidentTimeline(incident);

  const printButton = document.querySelector("#print-report");
  if (printButton) {
    printButton.addEventListener("click", () => window.print());
  }

  const regenerateButton = document.querySelector("#regenerate-report");
  if (regenerateButton) {
    regenerateButton.addEventListener("click", () => {
      const nextIncident = pickIncident();
      if (!nextIncident) return;
      state.activeIncident = nextIncident;
      localStorage.setItem("gcfCurrentIncident", JSON.stringify(nextIncident));
      const nextMatch = findBestLookupMatch(nextIncident);
      state.activeIOC = nextMatch;
      updateReport(nextIncident, nextMatch);
      renderIncidentTimeline(nextIncident);
    });
  }
}

function setActiveNav() {
  const path = window.location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll("[data-nav-link]").forEach((link) => {
    const href = link.getAttribute("href") || "";
    if (href === path) {
      link.classList.add("active");
    }
  });
}

function initCommonInteractions() {
  document.querySelectorAll("[data-animate]").forEach((item, index) => {
    item.style.animationDelay = `${index * 0.08}s`;
  });
}

async function bootstrap() {
  state.data = await Promise.all(Object.entries(DATA_FILES).map(async ([key, file]) => [key, await fetchJSON(file)])).then((entries) => Object.fromEntries(entries));

  setActiveNav();
  initCommonInteractions();

  const page = document.body.dataset.page;
  if (page === "landing") {
    renderLanding();
  }
  if (page === "dashboard") {
    renderDashboard();
  }
  if (page === "investigation") {
    initInvestigation();
  }
  if (page === "reports") {
    initReports();
  }
}

window.addEventListener("DOMContentLoaded", bootstrap);
