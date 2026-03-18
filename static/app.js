const form = document.querySelector("#analyze-form");
const statusNode = document.querySelector("#status");
const overviewSection = document.querySelector("#overview");
const summarySection = document.querySelector("#summary");
const detailsSection = document.querySelector("#details");
const evidenceSection = document.querySelector("#evidence-panel");
const rawSection = document.querySelector("#raw");
const rawJsonNode = document.querySelector("#raw-json");
const rawToggleButton = document.querySelector("#toggle-raw");
const modeInputs = document.querySelectorAll("input[name='view_mode']");

let lastResult = null;

const CVSS_LABELS = {
  AV: { N: "Attack Vector: Network", A: "Attack Vector: Adjacent", L: "Attack Vector: Local", P: "Attack Vector: Physical" },
  AC: { L: "Attack Complexity: Low", H: "Attack Complexity: High" },
  PR: { N: "Privileges Required: None", L: "Privileges Required: Low", H: "Privileges Required: High" },
  UI: { N: "User Interaction: None", R: "User Interaction: Required" },
  S: { U: "Scope: Unchanged", C: "Scope: Changed" },
  C: { N: "Confidentiality: None", L: "Confidentiality: Low", H: "Confidentiality: High" },
  I: { N: "Integrity: None", L: "Integrity: Low", H: "Integrity: High" },
  A: { N: "Availability: None", L: "Availability: Low", H: "Availability: High" },
};

function formatValue(value) {
  return value ?? "n/a";
}

function setText(id, value) {
  document.querySelector(id).textContent = formatValue(value);
}

function setHumanText(id, value) {
  document.querySelector(id).textContent = value || "n/a";
}

function formatScore(score, severity) {
  if (score === null || score === undefined) {
    return "n/a";
  }
  return severity ? `${score} (${severity})` : String(score);
}

function buildOverviewText(analysis, comparison, mode) {
  const changedCount = Object.keys(comparison.changed_metrics || {}).length;
  const fallbackCount = (analysis.evidence_quality?.fallback_metrics || []).length;
  const rescored = comparison.rescored_score;
  const original = comparison.original_score;
  if (mode === "strict") {
    if (rescored === null || rescored === undefined) {
      return `Strict mode did not produce a final score because ${fallbackCount} required metrics could not be supported directly from the references.`;
    }
    return `Strict mode produced a final score using only directly supported metrics, with no fallback-driven gaps left unresolved.`;
  }
  if (rescored === null || rescored === undefined) {
    return `Strict evidence was not enough to produce a final score. ${fallbackCount} metrics relied on fallback values in the non-strict run.`;
  }
  return `The independent re-score changed ${changedCount} metric${changedCount === 1 ? "" : "s"} and moved the score from ${formatValue(original)} to ${formatValue(rescored)}. ${fallbackCount} metric${fallbackCount === 1 ? "" : "s"} relied on fallback values.`;
}

function updatePill(severity, confidence) {
  const pill = document.querySelector("#severity-pill");
  pill.textContent = severity || "No score";
  pill.className = "pill";
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL") {
    pill.classList.add("critical");
  } else if (value === "HIGH") {
    pill.classList.add("high");
  } else if (value === "MEDIUM") {
    pill.classList.add("medium");
  } else if (value === "LOW") {
    pill.classList.add("low");
  }
  if (confidence === "low") {
    pill.classList.add("muted-pill");
  }
}

function parseVector(vector) {
  if (!vector || !vector.startsWith("CVSS:3.1/")) {
    return {};
  }
  const metrics = {};
  for (const token of vector.split("/").slice(1)) {
    const [key, value] = token.split(":");
    if (key && value) {
      metrics[key] = value;
    }
  }
  return metrics;
}

function vectorToHuman(vector) {
  if (!vector) {
    return "n/a";
  }
  const metrics = parseVector(vector);
  return ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    .filter((key) => metrics[key])
    .map((key) => CVSS_LABELS[key]?.[metrics[key]] || `${key}: ${metrics[key]}`)
    .join("\n");
}

function formatBool(value) {
  if (value === true) {
    return "Yes";
  }
  if (value === false) {
    return "No";
  }
  return formatValue(value);
}

function formatSource(value) {
  if (!value) {
    return "n/a";
  }
  if (value === "cna") {
    return "CNA";
  }
  return value;
}

function formatConfidence(value, isLowConfidence) {
  if (!value) {
    return "n/a";
  }
  return isLowConfidence ? `${value} confidence` : value;
}

function getSelectedMode() {
  const selected = document.querySelector("input[name='view_mode']:checked");
  return selected ? selected.value : "both";
}

function getModePayload(data, mode) {
  if (mode === "strict") {
    const strict = data.strict_analysis || {};
    const normal = data.analysis || {};
    return {
      analysis: strict,
      comparison: {
        original_vector: normal.comparison?.original_vector ?? null,
        original_score: normal.comparison?.original_score ?? null,
        original_source: normal.comparison?.original_source ?? null,
        rescored_vector: strict.vector,
        rescored_score: strict.score,
        rescored_severity: strict.severity,
        score_delta: strict.comparison?.score_delta ?? null,
        changed_metrics: strict.comparison?.changed_metrics || {},
      },
      strict: strict,
      modeLabel: "Strict mode",
    };
  }

  const normal = data.analysis || {};
  return {
    analysis: normal,
    comparison: normal.comparison || {},
    strict: data.strict_analysis || {},
    modeLabel: mode === "both" ? "Independent mode" : "Independent mode",
  };
}

function updateConfidenceStyles(confidence, isLowConfidence) {
  const badge = document.querySelector("#confidence-badge");
  const text = document.querySelector("#confidence");
  badge.className = "confidence-badge";
  text.className = "value-block confidence-text";

  const value = (confidence || "").toLowerCase();
  if (value === "high") {
    badge.classList.add("confidence-high");
    text.classList.add("confidence-high-text");
  } else if (value === "medium") {
    badge.classList.add("confidence-medium");
    text.classList.add("confidence-medium-text");
  } else {
    badge.classList.add("confidence-low");
    text.classList.add("confidence-low-text");
  }

  badge.textContent = isLowConfidence ? "Needs review" : value ? `${confidence} confidence` : "n/a";
}

function formatMetricCode(metric) {
  const labels = {
    AV: "Attack Vector",
    AC: "Attack Complexity",
    PR: "Privileges Required",
    UI: "User Interaction",
    S: "Scope",
    C: "Confidentiality",
    I: "Integrity",
    A: "Availability",
  };
  return labels[metric] || metric;
}

function formatMetricValue(metric, value) {
  if (!value) {
    return "n/a";
  }
  const label = CVSS_LABELS[metric]?.[value];
  if (!label) {
    return value;
  }
  const parts = label.split(": ");
  return parts[1] || label;
}

function renderChipRow(targetId, items, emptyLabel) {
  const container = document.querySelector(targetId);
  container.innerHTML = "";
  const values = items && items.length ? items : [emptyLabel];
  for (const item of values) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = item;
    container.appendChild(chip);
  }
}

function renderChangedMetrics(changedMetrics) {
  const container = document.querySelector("#changed-metrics");
  container.innerHTML = "";
  const entries = Object.entries(changedMetrics || {});
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "detail-empty";
    empty.textContent = "No metric changes from the published vector.";
    container.appendChild(empty);
    return;
  }

  for (const [metric, change] of entries) {
    const item = document.createElement("div");
    item.className = "detail-item";

    const title = document.createElement("strong");
    title.textContent = formatMetricCode(metric);

    const summary = document.createElement("p");
    summary.textContent = `${formatMetricValue(metric, change.original)} -> ${formatMetricValue(metric, change.rescored)}`;

    const reason = document.createElement("p");
    reason.className = "detail-note";
    reason.textContent = change.reason || "No rationale provided.";

    item.appendChild(title);
    item.appendChild(summary);
    item.appendChild(reason);
    container.appendChild(item);
  }
}

function renderEvidence(evidence) {
  const container = document.querySelector("#evidence-list");
  container.innerHTML = "";
  const entries = Object.entries(evidence || {}).filter(([, items]) => items && items.length);

  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "detail-empty";
    empty.textContent = "No direct evidence snippets were captured.";
    container.appendChild(empty);
    return;
  }

  for (const [metric, items] of entries) {
    const item = document.createElement("div");
    item.className = "detail-item";

    const title = document.createElement("strong");
    title.textContent = formatMetricCode(metric);

    const chips = document.createElement("div");
    chips.className = "chip-row evidence-chip-row";

    for (const evidenceItem of items) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `${formatMetricValue(metric, evidenceItem.value)} · ${evidenceItem.evidence_type}`;
      chips.appendChild(chip);
    }

    item.appendChild(title);
    item.appendChild(chips);

    for (const evidenceItem of items) {
      const block = document.createElement("div");
      block.className = "evidence-block";

      const rationale = document.createElement("p");
      rationale.className = "evidence-rationale";
      rationale.textContent = evidenceItem.rationale || "No rationale provided.";

      const snippet = document.createElement("p");
      snippet.className = "evidence-snippet";
      snippet.textContent = evidenceItem.snippet || "No snippet available.";

      const meta = document.createElement("p");
      meta.className = "detail-note";
      meta.textContent = `${evidenceItem.source_type || "unknown source"} | ${evidenceItem.url || "unknown URL"}`;

      block.appendChild(rationale);
      block.appendChild(snippet);
      block.appendChild(meta);
      item.appendChild(block);
    }

    container.appendChild(item);
  }
}

function showResults(data) {
  lastResult = data;
  const mode = getSelectedMode();
  const payload = getModePayload(data, mode);
  const analysis = payload.analysis || {};
  const comparison = payload.comparison || {};
  const strict = payload.strict || {};

  document.querySelector("#overview-title").textContent = `${data.cve_id} analysis`;
  document.querySelector("#overview-text").textContent = buildOverviewText(analysis, comparison, mode);
  setText("#original-score-big", formatScore(comparison.original_score, null));
  setText("#rescored-score-big", formatScore(comparison.rescored_score, comparison.rescored_severity));
  setText("#score-delta-big", comparison.score_delta);
  setText("#confidence-big", analysis.confidence);
  updateConfidenceStyles(analysis.confidence, analysis.low_confidence);
  updatePill(comparison.rescored_severity, analysis.confidence);

  setHumanText("#original-vector", vectorToHuman(comparison.original_vector));
  setText("#original-vector-raw", comparison.original_vector);
  setText("#original-score", comparison.original_score);
  setText("#original-source", formatSource(comparison.original_source));
  setHumanText("#rescored-vector", vectorToHuman(comparison.rescored_vector));
  setText("#rescored-vector-raw", comparison.rescored_vector);
  setText("#rescored-score", comparison.rescored_score);
  setText("#rescored-severity", comparison.rescored_severity);
  setText("#confidence", formatConfidence(analysis.confidence, analysis.low_confidence));
  setText(
    "#confidence-note",
    analysis.low_confidence
      ? "This result relies on fallback assumptions and should be reviewed."
      : "This result is mostly supported by direct evidence."
  );
  setText("#fallback-count", (analysis.evidence_quality?.fallback_metrics || []).length);
  setText("#reference-errors", (analysis.reference_fetch_errors || []).length);

  renderChangedMetrics(comparison.changed_metrics || {});
  renderChipRow(
    "#evidence-backed",
    (analysis.evidence_quality?.evidence_backed_metrics || []).map(formatMetricCode),
    "None"
  );
  renderChipRow(
    "#fallback-metrics",
    (analysis.evidence_quality?.fallback_metrics || []).map(formatMetricCode),
    "None"
  );
  renderChipRow(
    "#undetermined-metrics",
    (strict.evidence_quality?.undetermined_metrics || []).map(formatMetricCode),
    "None"
  );
  setText("#strict-status", strict.vector ? "Scored successfully" : "No final score in strict mode");
  setText("#strict-score", strict.score);
  setText("#strict-severity", strict.severity);
  setText("#strict-vector", strict.vector);
  renderEvidence(analysis.evidence || {});
  rawJsonNode.textContent = JSON.stringify(data, null, 2);
  rawJsonNode.classList.add("hidden");
  rawToggleButton.textContent = "Show raw JSON";

  overviewSection.classList.remove("hidden");
  summarySection.classList.remove("hidden");
  detailsSection.classList.remove("hidden");
  evidenceSection.classList.remove("hidden");
  rawSection.classList.remove("hidden");
}

for (const input of modeInputs) {
  input.addEventListener("change", () => {
    if (lastResult) {
      showResults(lastResult);
    }
  });
}

rawToggleButton.addEventListener("click", () => {
  const isHidden = rawJsonNode.classList.toggle("hidden");
  rawToggleButton.textContent = isHidden ? "Show raw JSON" : "Hide raw JSON";
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const cveId = document.querySelector("#cve_id").value.trim();
  if (!cveId) {
    statusNode.textContent = "Enter a CVE ID first.";
    return;
  }

  statusNode.textContent = `Analyzing ${cveId}...`;
  overviewSection.classList.add("hidden");
  summarySection.classList.add("hidden");
  detailsSection.classList.add("hidden");
  evidenceSection.classList.add("hidden");
  rawSection.classList.add("hidden");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: cveId }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Analysis failed");
    }

    showResults(data);
    statusNode.textContent = `Finished analyzing ${cveId}.`;
  } catch (error) {
    statusNode.textContent = error.message;
  }
});
