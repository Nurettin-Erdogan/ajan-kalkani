"use strict";

const API = {
  scenarios: "/api/scenarios",
  runs: "/api/runs",
  evaluations: "/api/evaluations",
  auditRuns: "/api/audit/runs?limit=8",
  auditIntegrity: "/api/audit/integrity",
  policyEvaluate: "/api/policy/evaluate",
  gatewaySessions: "/api/gateway/sessions",
};

const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

const state = {
  scenarios: [],
  running: false,
  evaluating: false,
  evaluatingPolicy: false,
};

const elements = {
  apiStatus: document.querySelector("#api-status"),
  scenarioSelect: document.querySelector("#scenario-select"),
  scenarioPreview: document.querySelector("#scenario-preview"),
  runButton: document.querySelector("#run-button"),
  runButtonLabel: document.querySelector("#run-button-label"),
  retryButton: document.querySelector("#retry-button"),
  notice: document.querySelector("#notice"),
  emptyState: document.querySelector("#empty-state"),
  loadingState: document.querySelector("#loading-state"),
  resultsGrid: document.querySelector("#results-grid"),
  resultsMeta: document.querySelector("#results-meta"),
  unprotectedResult: document.querySelector("#unprotected-result"),
  guardedResult: document.querySelector("#guarded-result"),
  evaluationButton: document.querySelector("#evaluation-button"),
  evaluationButtonLabel: document.querySelector("#evaluation-button-label"),
  evaluationStatus: document.querySelector("#evaluation-status"),
  evaluationStatusMark: document.querySelector("#evaluation-status-mark"),
  evaluationStatusTitle: document.querySelector("#evaluation-status-title"),
  evaluationStatusDetail: document.querySelector("#evaluation-status-detail"),
  evaluationMetrics: document.querySelector("#evaluation-metrics"),
  evaluationFailures: document.querySelector("#evaluation-failures"),
  auditRuns: document.querySelector("#audit-runs"),
  auditSummary: document.querySelector("#audit-summary"),
  policyForm: document.querySelector("#policy-form"),
  policyTask: document.querySelector("#policy-task"),
  policyAllow: document.querySelector("#policy-allow"),
  policyDeny: document.querySelector("#policy-deny"),
  policyApproval: document.querySelector("#policy-approval"),
  policyCalls: document.querySelector("#policy-calls"),
  policyMode: document.querySelector("#policy-mode"),
  policyButton: document.querySelector("#policy-button"),
  policyButtonLabel: document.querySelector("#policy-button-label"),
  policyNotice: document.querySelector("#policy-notice"),
  policyResults: document.querySelector("#policy-results"),
  gatewaySessionButton: document.querySelector("#gateway-session-button"),
  gatewaySessionResult: document.querySelector("#gateway-session-result"),
};

const DECISION_GROUPS = {
  error: ["error", "failed", "failure", "exception", "hata", "başarısız"],
  blocked: ["blocked", "block", "deny", "denied", "rejected", "prevented", "engellendi", "reddedildi"],
  executed: ["executed", "execute", "allow", "allowed", "completed", "success", "yürütüldü", "izin verildi"],
};

const FAILURE_METRIC_LABELS = {
  guarded_attack_success_rate: "Korumalı saldırı başarısı",
  guarded_task_success_rate: "Korumalı görev başarısı",
  safe_false_block_rate: "Güvenli görevde yanlış blok",
};

document.addEventListener("DOMContentLoaded", () => {
  elements.scenarioSelect.addEventListener("change", renderScenarioPreview);
  elements.runButton.addEventListener("click", runComparison);
  elements.retryButton.addEventListener("click", loadScenarios);
  elements.evaluationButton.addEventListener("click", runEvaluation);
  elements.policyForm.addEventListener("submit", runPolicyEvaluation);
  elements.gatewaySessionButton.addEventListener("click", createGatewaySession);
  loadScenarios();
  loadAuditRuns();
});

async function runPolicyEvaluation(event) {
  event.preventDefault();
  if (state.evaluatingPolicy) return;

  let calls;
  try {
    calls = parsePolicyCalls(elements.policyCalls.value);
  } catch (error) {
    setPolicyNotice(error.message || "Araç çağrıları okunamadı.");
    return;
  }

  const request = {
    contract: {
      task: elements.policyTask.value.trim(),
      allow: parseRuleList(elements.policyAllow.value),
      deny: parseRuleList(elements.policyDeny.value),
      approval_required: parseRuleList(elements.policyApproval.value),
    },
    calls,
    mode: elements.policyMode.value,
  };

  setPolicyRunning(true);
  setPolicyNotice("");
  elements.policyResults.hidden = true;

  try {
    const response = await fetchJson(API.policyEvaluate, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    renderPolicyEvaluation(response && typeof response === "object" ? response : {});
    elements.policyResults.hidden = false;
    setApiStatus("ready", "Politika değerlendirmesi tamamlandı");
  } catch (error) {
    setPolicyNotice(friendlyApiError(error));
  } finally {
    setPolicyRunning(false);
  }
}

async function createGatewaySession() {
  if (state.evaluatingPolicy) return;
  const task = elements.policyTask.value.trim();
  if (!task) {
    setPolicyNotice("Gateway oturumu için görev açıklaması gereklidir.");
    return;
  }

  const request = {
    name: task.slice(0, 120),
    ttl_minutes: 60,
    contract: {
      task,
      allow: parseRuleList(elements.policyAllow.value),
      deny: parseRuleList(elements.policyDeny.value),
      approval_required: parseRuleList(elements.policyApproval.value),
    },
  };

  setPolicyRunning(true);
  setPolicyNotice("");
  elements.gatewaySessionResult.hidden = true;
  try {
    const session = await fetchJson(API.gatewaySessions, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    renderGatewaySession(session && typeof session === "object" ? session : {});
    elements.gatewaySessionResult.hidden = false;
    setApiStatus("ready", "Gateway oturumu hazır");
  } catch (error) {
    setPolicyNotice(friendlyApiError(error));
  } finally {
    setPolicyRunning(false);
  }
}

function renderGatewaySession(session) {
  const sessionId = String(session.id || "");
  const endpoint = `/api/gateway/sessions/${encodeURIComponent(sessionId)}/authorize`;
  const expiresAt = formatAuditTime(session.expires_at);
  elements.gatewaySessionResult.innerHTML = `
    <div class="gateway-session-heading">
      <div>
        <p class="section-kicker">RUNTIME GATEWAY HAZIR</p>
        <h3>60 dakikalık sözleşme oturumu oluşturuldu</h3>
      </div>
      <span class="lab-safety-badge">AKTİF</span>
    </div>
    <div class="gateway-session-meta">
      <span><strong>Oturum</strong><code>${escapeHtml(sessionId)}</code></span>
      <span><strong>Süre sonu</strong><code>${escapeHtml(expiresAt)}</code></span>
      <span><strong>Contract hash</strong><code>${escapeHtml(String(session.contract_hash || "").slice(0, 16))}…</code></span>
    </div>
    <p>Ajanınız her araç çağrısından önce aşağıdaki adrese <code>POST</code> isteği göndermeli ve yalnızca <code>decision.allowed=true</code> ise aracı çalıştırmalıdır.</p>
    <code class="gateway-endpoint">${escapeHtml(endpoint)}</code>
  `;
}

function parseRuleList(value) {
  return [...new Set(String(value || "").split(/[\n,]/).map((item) => item.trim()).filter(Boolean))];
}

function parsePolicyCalls(value) {
  const lines = String(value || "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) throw new Error("En az bir araç çağrısı yazmalısınız.");
  if (lines.length > 50) throw new Error("Tek değerlendirmede en fazla 50 araç çağrısı kullanılabilir.");

  return lines.map((line, index) => {
    const [rawTool, rawLabels = ""] = line.split("|", 2);
    const tool = rawTool.trim();
    if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(tool)) {
      throw new Error(`${index + 1}. satırdaki araç adı geçersiz: ${tool || "boş"}`);
    }
    return {
      tool,
      origin: "policy-laboratory",
      data_labels: parseRuleList(rawLabels),
      arguments: {},
    };
  });
}

function renderPolicyEvaluation(response) {
  const summary = response.summary && typeof response.summary === "object" ? response.summary : {};
  const findings = Array.isArray(response.findings) ? response.findings : [];
  const results = Array.isArray(response.results) ? response.results : [];
  const modeLabel = response.mode === "unprotected" ? "Korumasız" : "Korumalı";

  elements.policyResults.innerHTML = `
    <div class="policy-result-heading">
      <div>
        <p class="section-kicker">DEĞERLENDİRME SONUCU</p>
        <h3>${escapeHtml(modeLabel)} mod · ${escapeHtml(String(summary.total_calls ?? results.length))} çağrı</h3>
      </div>
      <span class="risk-chip risk-${escapeAttribute(normalizeRisk(summary.highest_risk))}">
        ${escapeHtml(riskLabel(normalizeRisk(summary.highest_risk)))}
      </span>
    </div>
    <div class="policy-summary-grid">
      ${policySummaryCard("İzin verilen", summary.allowed_calls, "is-positive")}
      ${policySummaryCard("Engellenen", summary.blocked_calls, "is-negative")}
      ${policySummaryCard("Onay bekleyen", summary.approval_requests, "")}
    </div>
    ${contractFindingsTemplate(findings)}
    <div class="policy-call-results">
      ${results.map(policyResultRow).join("") || '<p class="audit-empty">Değerlendirme sonucu dönmedi.</p>'}
    </div>
  `;
}

function policySummaryCard(label, value, tone) {
  const safeValue = Number.isFinite(Number(value)) ? Math.max(0, Math.round(Number(value))) : 0;
  return `<div class="policy-summary-card ${tone}"><span>${escapeHtml(label)}</span><strong>${safeValue}</strong></div>`;
}

function contractFindingsTemplate(findings) {
  if (!findings.length) {
    return `
      <section class="contract-findings is-clean">
        <strong>Sözleşme analizi temiz</strong>
        <span>Yaygın aşırı yetki veya kural çakışması bulunmadı.</span>
      </section>
    `;
  }

  return `
    <section class="contract-findings">
      <h4>Sözleşme analizi</h4>
      <div class="finding-list">
        ${findings
          .map((finding) => {
            const severity = ["critical", "warning", "info"].includes(finding.severity)
              ? finding.severity
              : "info";
            const patterns = Array.isArray(finding.patterns) && finding.patterns.length
              ? `<code>${escapeHtml(finding.patterns.join(", "))}</code>`
              : "";
            return `
              <article class="finding finding-${severity}">
                <span>${severity === "critical" ? "KRİTİK" : severity === "warning" ? "UYARI" : "BİLGİ"}</span>
                <div><strong>${escapeHtml(finding.message || "Sözleşme bulgusu")}</strong>${patterns}</div>
              </article>
            `;
          })
          .join("")}
      </div>
    </section>
  `;
}

function policyResultRow(item) {
  const decision = item && item.decision && typeof item.decision === "object" ? item.decision : {};
  const allowed = decision.allowed === true;
  const requiresApproval = decision.requires_approval === true;
  const stateClass = allowed ? "is-allowed" : requiresApproval ? "is-approval" : "is-blocked";
  const stateLabel = allowed ? "İZİN" : requiresApproval ? "ONAY GEREKLİ" : "ENGELLENDİ";
  const labels = Array.isArray(item.data_labels) ? item.data_labels : [];
  return `
    <article class="policy-call ${stateClass}">
      <span class="policy-call-index">${escapeHtml(item.position || "–")}</span>
      <div class="policy-call-main">
        <div><code>${escapeHtml(item.tool || "bilinmeyen araç")}</code><span>${escapeHtml(stateLabel)}</span></div>
        <p>${escapeHtml(decision.reason || "Karar açıklaması bulunmuyor.")}</p>
        <small>${escapeHtml(decision.rule_id || "kural yok")}${labels.length ? ` · etiketler: ${escapeHtml(labels.join(", "))}` : ""}</small>
      </div>
    </article>
  `;
}

function setPolicyRunning(running) {
  state.evaluatingPolicy = running;
  elements.policyButton.disabled = running;
  elements.gatewaySessionButton.disabled = running;
  elements.policyButton.classList.toggle("is-loading", running);
  elements.policyButton.setAttribute("aria-busy", String(running));
  elements.policyButtonLabel.textContent = running ? "Sözleşme değerlendiriliyor" : "Sözleşmeyi değerlendir";
}

function setPolicyNotice(message) {
  elements.policyNotice.hidden = !message;
  elements.policyNotice.textContent = message || "";
}

async function runEvaluation() {
  if (state.evaluating) return;

  setEvaluationRunning(true);
  setEvaluationStatus(
    "loading",
    "Güvenlik paketi çalıştırılıyor",
    "Tüm senaryolar korumasız ve Ajan Kalkanı korumalı modlarda değerlendiriliyor…",
  );
  elements.evaluationMetrics.hidden = true;
  elements.evaluationMetrics.innerHTML = "";
  elements.evaluationFailures.hidden = true;
  elements.evaluationFailures.innerHTML = "";

  try {
    const report = await fetchJson(API.evaluations, { method: "POST" });
    renderEvaluation(report && typeof report === "object" ? report : {});
    loadAuditRuns();
    setApiStatus("ready", "Ajan Kalkanı CI tamamlandı");
  } catch (error) {
    setEvaluationStatus(
      "error",
      "Değerlendirme çalıştırılamadı",
      friendlyApiError(error),
    );
    setApiStatus("error", "Ajan Kalkanı CI hatası");
  } finally {
    setEvaluationRunning(false);
  }
}

function renderEvaluation(report) {
  const metrics = report.metrics && typeof report.metrics === "object" ? report.metrics : {};
  const thresholds = report.thresholds && typeof report.thresholds === "object" ? report.thresholds : {};
  const passed = report.passed === true;
  const scenarioCount = safeCount(metrics.scenario_count);
  const attackScenarioCount = safeCount(metrics.attack_scenario_count);
  const baselineAttackRate = formatRate(metrics.baseline_attack_success_rate);
  const guardedAttackRate = numericRate(metrics.guarded_attack_success_rate);
  const taskSuccessRate = numericRate(metrics.guarded_task_success_rate);
  const falseBlockRate = numericRate(metrics.safe_false_block_rate);
  const blockedCalls = safeCount(metrics.total_guarded_blocks);
  const guardedAttackTarget = numericRate(thresholds.max_guarded_attack_success) ?? 0;
  const taskSuccessTarget = numericRate(thresholds.min_guarded_task_success) ?? 1;
  const falseBlockTarget = numericRate(thresholds.max_safe_false_block_rate) ?? 0;

  setEvaluationStatus(
    passed ? "passed" : "failed",
    passed ? "Ajan Kalkanı CI kapısı geçti" : "Ajan Kalkanı CI kapısı kaldı",
    `${scenarioCount} senaryo · ${attackScenarioCount} saldırı testi · Korumasız saldırı başarısı ${baselineAttackRate}`,
  );

  const cards = [
    {
      label: "Korumalı saldırı başarısı",
      value: formatRate(guardedAttackRate),
      detail: `Hedef en fazla ${formatRate(guardedAttackTarget)}`,
      tone:
        guardedAttackRate !== null && guardedAttackRate <= guardedAttackTarget
          ? "is-positive"
          : "is-negative",
    },
    {
      label: "Korumalı görev başarısı",
      value: formatRate(taskSuccessRate),
      detail: `Hedef en az ${formatRate(taskSuccessTarget)}`,
      tone:
        taskSuccessRate !== null && taskSuccessRate >= taskSuccessTarget
          ? "is-positive"
          : "is-negative",
    },
    {
      label: "Güvenli görevde yanlış blok",
      value: formatRate(falseBlockRate),
      detail: `Hedef en fazla ${formatRate(falseBlockTarget)}`,
      tone:
        falseBlockRate !== null && falseBlockRate <= falseBlockTarget
          ? "is-positive"
          : "is-negative",
    },
    {
      label: "Politika tarafından engellenen",
      value: String(blockedCalls),
      detail: "Araç çağrısı",
      tone: "",
    },
  ];

  elements.evaluationMetrics.innerHTML = cards
    .map(
      (card) => `
        <article class="evaluation-metric ${card.tone}">
          <span>${escapeHtml(card.label)}</span>
          <strong>${escapeHtml(card.value)}</strong>
          <small>${escapeHtml(card.detail)}</small>
        </article>
      `,
    )
    .join("");
  elements.evaluationMetrics.hidden = false;

  const failures = Array.isArray(report.failures) ? report.failures : [];
  if (!passed) {
    const messages = failures.length
      ? failures.map(readableFailure)
      : ["En az bir güvenlik veya görev başarısı eşiği karşılanmadı."];
    elements.evaluationFailures.innerHTML = `
      <strong>İncelenmesi gereken kontroller</strong>
      <ul>${messages.map((message) => `<li>${escapeHtml(message)}</li>`).join("")}</ul>
    `;
    elements.evaluationFailures.hidden = false;
  }
}

function readableFailure(failure) {
  if (typeof failure === "string" || typeof failure === "number") return String(failure);
  if (!failure || typeof failure !== "object") return "Bilinmeyen değerlendirme hatası";

  const metricLabel = FAILURE_METRIC_LABELS[failure.metric];
  const actual = numericRate(failure.actual);
  const threshold = numericRate(failure.threshold);
  if (metricLabel && actual !== null && threshold !== null) {
    const limit = failure.operator === ">=" ? "en az" : "en fazla";
    return `${metricLabel}: ölçülen ${formatRate(actual)}, beklenen ${limit} ${formatRate(threshold)}.`;
  }

  const message = failure.message || failure.reason || failure.detail || failure.name;
  const scenario = failure.scenario_name || failure.scenario_id;
  if (message && scenario) return `${scenario}: ${message}`;
  if (message) return String(message);
  if (scenario) return `${scenario} senaryosu eşiği karşılamadı.`;
  return safeStringify(failure);
}

function setEvaluationRunning(isRunning) {
  state.evaluating = isRunning;
  elements.evaluationButton.disabled = isRunning;
  elements.evaluationButton.classList.toggle("is-loading", isRunning);
  elements.evaluationButton.setAttribute("aria-busy", String(isRunning));
  elements.evaluationButtonLabel.textContent = isRunning
    ? "Güvenlik paketi çalıştırılıyor"
    : "Güvenlik paketini çalıştır";
}

function setEvaluationStatus(stateName, title, detail) {
  elements.evaluationStatus.dataset.state = stateName;
  elements.evaluationStatusMark.textContent =
    stateName === "loading"
      ? ""
      : stateName === "passed"
        ? "✓"
        : stateName === "failed" || stateName === "error"
          ? "!"
          : "CI";
  elements.evaluationStatusTitle.textContent = title;
  elements.evaluationStatusDetail.textContent = detail;
}

function numericRate(value) {
  if (value == null || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function formatRate(value) {
  if (value == null || value === "") return "—";
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return "—";
  const percent = parsed <= 1 ? parsed * 100 : parsed;
  return `%${percent.toLocaleString("tr-TR", {
    minimumFractionDigits: Number.isInteger(percent) ? 0 : 1,
    maximumFractionDigits: 1,
  })}`;
}

function safeCount(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.round(parsed) : 0;
}

async function loadScenarios() {
  setNotice("");
  setApiStatus("loading", "Senaryolar yükleniyor");
  elements.retryButton.hidden = true;
  elements.scenarioSelect.disabled = true;
  elements.runButton.disabled = true;
  elements.scenarioSelect.innerHTML = "<option>Senaryolar yükleniyor…</option>";
  showScenarioPlaceholder();

  try {
    const payload = await fetchJson(API.scenarios);
    const scenarios = Array.isArray(payload)
      ? payload
      : Array.isArray(payload && payload.scenarios)
        ? payload.scenarios
        : [];

    state.scenarios = scenarios.filter((scenario) => scenario && scenario.id != null);

    if (state.scenarios.length === 0) {
      elements.scenarioSelect.innerHTML = "<option>Henüz senaryo bulunmuyor</option>";
      elements.scenarioPreview.innerHTML = emptyInline(
        "API bağlantısı kuruldu ancak çalıştırılabilir bir senaryo dönmedi.",
      );
      setApiStatus("ready", "API bağlı");
      setNotice("Henüz test senaryosu eklenmemiş. Backend'e en az bir senaryo ekleyin.", "info");
      return;
    }

    elements.scenarioSelect.innerHTML = state.scenarios
      .map(
        (scenario) =>
          `<option value="${escapeAttribute(String(scenario.id))}">${escapeHtml(
            scenario.name || `Senaryo ${scenario.id}`,
          )}</option>`,
      )
      .join("");
    elements.scenarioSelect.disabled = false;
    elements.runButton.disabled = false;
    setApiStatus("ready", `${state.scenarios.length} senaryo hazır`);
    renderScenarioPreview();
  } catch (error) {
    state.scenarios = [];
    elements.scenarioSelect.innerHTML = "<option>Senaryolar alınamadı</option>";
    elements.scenarioPreview.innerHTML = emptyInline(
      "Senaryo servisine ulaşılamadı. API çalıştığında burası otomatik deney seçimine dönüşür.",
    );
    elements.retryButton.hidden = false;
    setApiStatus("error", "API bağlantısı yok");
    setNotice(friendlyApiError(error));
  }
}

function renderScenarioPreview() {
  const scenario = getSelectedScenario();
  if (!scenario) {
    showScenarioPlaceholder();
    return;
  }

  elements.scenarioPreview.innerHTML = `
    <div class="scenario-preview-top">
      <h3>${escapeHtml(scenario.name || "İsimsiz senaryo")}</h3>
      <span class="category-chip">${escapeHtml(scenario.category || "GENEL")}</span>
    </div>
    <p class="scenario-description">${escapeHtml(
      scenario.description || "Bu senaryo için açıklama sağlanmadı.",
    )}</p>
    <p class="task-brief">
      <strong>GÖREV</strong>
      <span>${escapeHtml(scenario.task || "Görev bilgisi sağlanmadı.")}</span>
    </p>
  `;
}

async function runComparison() {
  if (state.running) return;

  const scenario = getSelectedScenario();
  if (!scenario) {
    setNotice("Çalıştırmak için önce geçerli bir senaryo seçin.");
    return;
  }

  setRunning(true);
  setNotice("");
  elements.emptyState.hidden = true;
  elements.resultsGrid.hidden = true;
  elements.loadingState.hidden = false;
  elements.resultsMeta.textContent = "İki mod paralel olarak çalıştırılıyor…";

  const startedAt = performance.now();
  const outcomes = await Promise.allSettled([
    createRun(scenario.id, "unprotected"),
    createRun(scenario.id, "guarded"),
  ]);
  const elapsed = Math.max(0, Math.round(performance.now() - startedAt));

  elements.loadingState.hidden = true;
  elements.resultsGrid.hidden = false;

  renderSettledResult(elements.unprotectedResult, outcomes[0], "unprotected", scenario);
  renderSettledResult(elements.guardedResult, outcomes[1], "guarded", scenario);

  const successCount = outcomes.filter((outcome) => outcome.status === "fulfilled").length;
  if (successCount === 2) {
    elements.resultsMeta.textContent = `Karşılaştırma tamamlandı · ${formatDuration(elapsed)}`;
    setApiStatus("ready", "API bağlı");
  } else if (successCount === 1) {
    elements.resultsMeta.textContent = `Bir mod tamamlandı · ${formatDuration(elapsed)}`;
    setNotice("Modlardan biri tamamlanamadı. Başarılı olan sonuç aşağıda gösteriliyor.");
  } else {
    elements.resultsMeta.textContent = "Karşılaştırma tamamlanamadı";
    setApiStatus("error", "API bağlantısı yok");
    setNotice(friendlyApiError(outcomes[0].reason));
  }

  setRunning(false);
  loadAuditRuns();

  const resultsTop = document.querySelector("#results-title");
  if (resultsTop) resultsTop.focus?.({ preventScroll: true });
  document.querySelector("#results-title")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadAuditRuns() {
  try {
    const [runs, integrity] = await Promise.all([
      fetchJson(API.auditRuns),
      fetchJson(API.auditIntegrity),
    ]);
    renderAuditRuns(Array.isArray(runs) ? runs : [], integrity);
  } catch (error) {
    elements.auditSummary.textContent = "Denetim geçmişi yüklenemedi";
    elements.auditSummary.classList.remove("is-valid");
    elements.auditSummary.classList.add("is-invalid");
    elements.auditRuns.innerHTML = `<p class="audit-empty">${escapeHtml(friendlyApiError(error))}</p>`;
  }
}

function renderAuditRuns(runs, integrity) {
  const integrityValid = integrity && integrity.valid === true;
  const integrityLabel = integrityValid ? "bütünlük doğrulandı" : "bütünlük kontrolü gerekli";
  elements.auditSummary.textContent = runs.length
    ? `${runs.length} son koşu · ${integrityLabel}`
    : integrityValid
      ? "Henüz kayıt yok · bütünlük doğrulandı"
      : integrityLabel;
  elements.auditSummary.classList.toggle("is-valid", integrityValid);
  elements.auditSummary.classList.toggle("is-invalid", !integrityValid);
  if (!runs.length) {
    elements.auditRuns.innerHTML = '<p class="audit-empty">İlk karşılaştırmayı çalıştırdığınızda redakte edilmiş kayıt burada görünecek.</p>';
    return;
  }

  elements.auditRuns.innerHTML = runs
    .map((run) => {
      const compromised = run.attack_success === true;
      const protectedRun = run.status === "protected";
      const mode = run.mode === "guarded" ? "Korumalı" : "Korumasız";
      const outcome = compromised ? "Saldırı başarılı" : protectedRun ? "Saldırı engellendi" : "Görev tamamlandı";
      return `
        <article class="audit-run ${compromised ? "is-risk" : "is-safe"}">
          <div>
            <strong>${escapeHtml(run.scenario_name || run.scenario_id || "Bilinmeyen senaryo")}</strong>
            <span>${escapeHtml(mode)} · ${escapeHtml(formatAuditTime(run.created_at))}</span>
          </div>
          <span class="audit-outcome">${escapeHtml(outcome)}</span>
        </article>
      `;
    })
    .join("");
}

function formatAuditTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "zaman bilinmiyor";
  return date.toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" });
}

async function createRun(scenarioId, mode) {
  return fetchJson(API.runs, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id: scenarioId, mode }),
  });
}

function renderSettledResult(container, outcome, mode, scenario) {
  if (outcome.status === "fulfilled") {
    container.innerHTML = resultTemplate(outcome.value || {}, mode, scenario);
    return;
  }

  container.innerHTML = errorTemplate(outcome.reason);
}

function resultTemplate(result, mode, scenario) {
  const events = getEvents(result);
  const metrics = result.metrics && typeof result.metrics === "object" ? result.metrics : {};
  const attackSucceeded = Boolean(result.attack_success);
  const isNormalTask =
    !attackSucceeded &&
    scenario &&
    String(scenario.category || "").toLocaleLowerCase("tr-TR") === "normal-task";
  const taskSucceeded = Boolean(result.task_success);
  const blockedCount = getCount(metrics, [
    "blocked_calls",
    "blocked_count",
    "blocked",
    "denied_count",
    "policy_blocks",
  ], countDecisions(events, "blocked"));
  const executedCount = getCount(metrics, [
    "executed_calls",
    "executed_count",
    "executed",
    "allowed_count",
    "tool_calls",
  ], countDecisions(events, "executed"));
  const duration = getDuration(result, metrics);
  const outcomeClass = attackSucceeded ? "is-danger" : "is-safe";
  const attackLabel = isNormalTask
    ? "Normal görev"
    : attackSucceeded
      ? "Saldırı başarılı"
      : "Saldırı engellendi";
  const outcomeDetail = isNormalTask
    ? "Bu çalıştırmada saldırı senaryosu yok."
    : attackSucceeded
      ? "Yetkisiz eylem sandbox içinde yürütüldü."
      : "Tehlikeli araç çağrısı hedefe ulaşamadı.";
  const attackMetric = isNormalTask
    ? { value: "Yok", tone: "is-positive" }
    : {
        value: attackSucceeded ? "Başarılı" : "Engellendi",
        tone: attackSucceeded ? "is-negative" : "is-positive",
      };

  return `
    <div class="outcome-banner ${outcomeClass}">
      <span class="outcome-icon" aria-hidden="true">${outcomeIcon(attackSucceeded)}</span>
      <div class="outcome-copy">
        <strong>${attackLabel}</strong>
        <span>${outcomeDetail}</span>
      </div>
      <span class="duration-chip">${escapeHtml(formatDuration(duration))}</span>
    </div>

    ${result.summary ? `<p class="run-summary">${escapeHtml(result.summary)}</p>` : ""}

    <div class="metric-grid" aria-label="Çalıştırma ölçümleri">
      ${metricTemplate("Görev", taskSucceeded ? "Başarılı" : "Başarısız", taskSucceeded ? "is-positive" : "is-negative")}
      ${metricTemplate("Saldırı", attackMetric.value, attackMetric.tone)}
      ${metricTemplate("Engellenen", String(blockedCount), blockedCount > 0 ? "is-positive" : "")}
      ${metricTemplate("Çalıştırılan", String(executedCount), "")}
    </div>

    <section class="result-section" aria-label="Görev sözleşmesi">
      <div class="result-section-heading">
        <h4>Görev sözleşmesi</h4>
        <span>${mode === "guarded" ? "ENFORCED" : "BYPASSED"}</span>
      </div>
      ${contractTemplate(result.contract, mode)}
    </section>

    <section class="result-section" aria-label="Olay zaman çizelgesi">
      <div class="result-section-heading">
        <h4>Olay zaman çizelgesi</h4>
        <span>${events.length} OLAY</span>
      </div>
      ${timelineTemplate(events)}
    </section>
  `;
}

function metricTemplate(label, value, valueClass) {
  return `
    <div class="metric">
      <span>${escapeHtml(label)}</span>
      <strong class="${valueClass}">${escapeHtml(value)}</strong>
    </div>
  `;
}

function contractTemplate(contract, mode) {
  if (!contract || typeof contract !== "object") {
    return `<div class="contract-box">${emptyInline(
      mode === "unprotected"
        ? "Korumasız modda görev sözleşmesi uygulanmadı."
        : "Bu çalıştırma için sözleşme verisi dönmedi.",
    )}</div>`;
  }

  const allow = contractList(contract, ["allow", "allowed", "allowed_tools", "permissions"]);
  const deny = contractList(contract, ["deny", "denied", "denied_tools", "blocked"]);
  const approval = contractList(contract, [
    "approval_required",
    "requires_approval",
    "approval",
  ]);

  if (!allow.length && !deny.length && !approval.length) {
    return `<div class="contract-box">${emptyInline("Sözleşmede gösterilebilir izin kuralı bulunmuyor.")}</div>`;
  }

  const rows = [
    contractRow("ALLOW", "allow", allow),
    contractRow("DENY", "deny", deny),
    approval.length ? contractRow("ONAY", "approval", approval) : "",
  ].join("");

  return `<div class="contract-box">${rows}</div>`;
}

function contractRow(label, type, values) {
  const content = values.length
    ? values.map((value) => `<span class="contract-chip">${escapeHtml(value)}</span>`).join("")
    : `<span class="empty-inline">Kural yok</span>`;

  return `
    <div class="contract-row">
      <span class="contract-label ${type}">${label}</span>
      <div class="contract-items">${content}</div>
    </div>
  `;
}

function contractList(contract, keys) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(contract, key)) {
      return valueToList(contract[key]);
    }
  }
  return [];
}

function valueToList(value) {
  if (Array.isArray(value)) {
    return value.map(readableRule).filter(Boolean);
  }

  if (value && typeof value === "object") {
    return Object.entries(value)
      .filter(([, enabled]) => enabled !== false && enabled != null)
      .map(([name, detail]) => {
        if (detail === true) return name;
        if (typeof detail === "string" || typeof detail === "number") return `${name}: ${detail}`;
        return name;
      });
  }

  if (typeof value === "string" || typeof value === "number") {
    return [String(value)];
  }

  return [];
}

function readableRule(rule) {
  if (typeof rule === "string" || typeof rule === "number") return String(rule);
  if (!rule || typeof rule !== "object") return "";
  return String(rule.name || rule.tool || rule.action || rule.permission || safeStringify(rule));
}

function timelineTemplate(events) {
  if (!events.length) {
    return `<div class="contract-box">${emptyInline("Bu çalıştırma için olay izi dönmedi.")}</div>`;
  }

  return `
    <ol class="timeline">
      ${events
        .map((event, index) => {
          const decisionGroup = normalizeDecision(event.decision);
          const risk = normalizeRisk(event.risk);
          const decisionLabel = formatDecisionLabel(event.decision, decisionGroup);
          const actor = event.actor || "agent";
          const action = event.action || "adım";
          const title = event.title || `Olay ${index + 1}`;
          const detail = event.detail || "Bu olay için ek ayrıntı sağlanmadı.";

          return `
            <li class="timeline-item is-${decisionGroup}">
              <span class="timeline-dot" aria-hidden="true"></span>
              <div class="timeline-content">
                <div class="timeline-meta">
                  <span class="actor-chip">${escapeHtml(actor)}</span>
                  <span class="decision-chip is-${decisionGroup}">${escapeHtml(decisionLabel)}</span>
                  <span class="risk-chip risk-${risk}">${escapeHtml(riskLabel(risk))}</span>
                </div>
                <h5>${escapeHtml(title)}</h5>
                <code class="timeline-action">${escapeHtml(action)}</code>
                <p class="timeline-detail">${escapeHtml(detail)}</p>
              </div>
            </li>
          `;
        })
        .join("")}
    </ol>
  `;
}

function errorTemplate(error) {
  return `
    <div class="result-error" role="alert">
      <svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">
        <circle cx="16" cy="16" r="12" />
        <path d="M16 9v8M16 22h.01" />
      </svg>
      <strong>Bu mod çalıştırılamadı</strong>
      <p>${escapeHtml(friendlyApiError(error))}</p>
    </div>
  `;
}

function getEvents(result) {
  const source = Array.isArray(result.events)
    ? result.events
    : Array.isArray(result.traces)
      ? result.traces
      : [];

  return source.map((event) => (event && typeof event === "object" ? event : { detail: String(event) }));
}

function getCount(metrics, keys, fallback) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(metrics, key)) {
      const parsed = Number(metrics[key]);
      if (Number.isFinite(parsed) && parsed >= 0) return Math.round(parsed);
    }
  }
  return fallback;
}

function getDuration(result, metrics) {
  const candidates = [result.duration_ms, metrics.duration_ms, metrics.latency_ms];
  for (const value of candidates) {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  }
  return 0;
}

function countDecisions(events, group) {
  return events.filter((event) => normalizeDecision(event.decision) === group).length;
}

function normalizeDecision(decision) {
  const normalized = String(decision || "").trim().toLocaleLowerCase("tr-TR");
  if (DECISION_GROUPS.error.some((token) => normalized.includes(token))) return "error";
  if (DECISION_GROUPS.blocked.some((token) => normalized.includes(token))) return "blocked";
  if (DECISION_GROUPS.executed.some((token) => normalized.includes(token))) return "executed";
  return "neutral";
}

function formatDecisionLabel(decision, group) {
  const normalized = String(decision || "").trim().toLocaleLowerCase("tr-TR");
  if (group === "error") return "Hata";
  if (group === "blocked") return "Engellendi";
  if (group === "executed") {
    return normalized.includes("allow") || normalized.includes("izin")
      ? "İzin verildi"
      : "Yürütüldü";
  }
  if (normalized === "observed" || normalized === "gözlemlendi") return "Gözlemlendi";
  return decision ? String(decision) : "İzlendi";
}

function normalizeRisk(risk) {
  const normalized = String(risk || "unknown").trim().toLowerCase();
  if (["critical", "kritik"].includes(normalized)) return "critical";
  if (["high", "yüksek", "yuksek"].includes(normalized)) return "high";
  if (["medium", "orta"].includes(normalized)) return "medium";
  if (["low", "düşük", "dusuk"].includes(normalized)) return "low";
  return "unknown";
}

function riskLabel(risk) {
  const labels = {
    critical: "Kritik risk",
    high: "Yüksek risk",
    medium: "Orta risk",
    low: "Düşük risk",
    unknown: "Risk belirtilmedi",
  };
  return labels[risk] || labels.unknown;
}

function outcomeIcon(attackSucceeded) {
  return attackSucceeded
    ? `<svg viewBox="0 0 24 24" focusable="false"><path d="M12 3 21 20H3L12 3Z"/><path d="M12 9v5M12 18h.01"/></svg>`
    : `<svg viewBox="0 0 24 24" focusable="false"><path d="M12 2.8 20 5.7v6.1c0 5-3 9-8 11.1-5-2.1-8-6.1-8-11.1V5.7L12 2.8Z"/><path d="m8.5 12 2.3 2.3 4.8-4.9"/></svg>`;
}

async function fetchJson(url, options = {}) {
  const { signal: externalSignal, ...fetchOptions } = options;
  const timeoutController = externalSignal ? null : new AbortController();
  const activeSignal = externalSignal || timeoutController.signal;
  let timeoutTriggered = false;
  const timeoutId = timeoutController
    ? window.setTimeout(() => {
        timeoutTriggered = true;
        timeoutController.abort();
      }, DEFAULT_REQUEST_TIMEOUT_MS)
    : null;

  try {
    let response;
    try {
      response = await fetch(url, {
        ...fetchOptions,
        signal: activeSignal,
        headers: {
          Accept: "application/json",
          ...(fetchOptions.headers || {}),
        },
      });
    } catch (error) {
      if (timeoutTriggered) throw createTimeoutError();
      if (activeSignal.aborted || error?.name === "AbortError") throw createAbortError();

      const networkError = new Error("API sunucusuna bağlantı kurulamadı.");
      networkError.cause = error;
      networkError.isNetworkError = true;
      throw networkError;
    }

    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (response.status !== 204) {
      try {
        data = contentType.includes("application/json") ? await response.json() : await response.text();
      } catch (error) {
        if (timeoutTriggered) throw createTimeoutError();
        if (activeSignal.aborted || error?.name === "AbortError") throw createAbortError();
        data = null;
      }
    }

    if (!response.ok) {
      const detail =
        data && typeof data === "object"
          ? data.detail || data.message || data.error
          : typeof data === "string"
            ? data
            : "";
      const error = new Error(detail || `API ${response.status} durum kodu döndürdü.`);
      error.status = response.status;
      throw error;
    }

    return data;
  } finally {
    if (timeoutId !== null) window.clearTimeout(timeoutId);
  }
}

function createTimeoutError() {
  const error = new Error("API 15 saniye içinde yanıt vermedi.");
  error.isTimeoutError = true;
  return error;
}

function createAbortError() {
  const error = new Error("İstek iptal edildi.");
  error.isAbortError = true;
  return error;
}

function friendlyApiError(error) {
  if (error && error.isTimeoutError) {
    return "API 15 saniye içinde yanıt vermedi. Sunucunun çalıştığını kontrol edip yeniden deneyin.";
  }

  if (error && error.isAbortError) {
    return "İstek iptal edildi. Hazır olduğunuzda yeniden deneyebilirsiniz.";
  }

  if (error && error.isNetworkError) {
    return "Ajan Kalkanı API'sine ulaşılamadı. Backend'in çalıştığını kontrol edip yeniden deneyin.";
  }

  if (error && error.status === 404) {
    return "İstenen API uç noktası bulunamadı. Backend sürümü bu arayüzle uyumlu olmayabilir.";
  }

  if (error && error.status >= 500) {
    return "Sandbox çalıştırılırken sunucu tarafında bir hata oluştu. Biraz sonra yeniden deneyin.";
  }

  const message = error && error.message ? String(error.message) : "Bilinmeyen bir bağlantı hatası oluştu.";
  return message.length > 220 ? `${message.slice(0, 217)}…` : message;
}

function getSelectedScenario() {
  const selectedId = elements.scenarioSelect.value;
  return state.scenarios.find((scenario) => String(scenario.id) === String(selectedId)) || null;
}

function setRunning(isRunning) {
  state.running = isRunning;
  elements.scenarioSelect.disabled = isRunning || state.scenarios.length === 0;
  elements.runButton.disabled = isRunning || state.scenarios.length === 0;
  elements.runButton.classList.toggle("is-loading", isRunning);
  elements.runButton.setAttribute("aria-busy", String(isRunning));
  elements.runButtonLabel.textContent = isRunning
    ? "İki mod çalıştırılıyor"
    : "Karşılaştırmayı çalıştır";
}

function setApiStatus(type, text) {
  elements.apiStatus.classList.remove("is-ready", "is-error");
  if (type === "ready") elements.apiStatus.classList.add("is-ready");
  if (type === "error") elements.apiStatus.classList.add("is-error");
  elements.apiStatus.lastChild.textContent = ` ${text}`;
}

function setNotice(message, type = "error") {
  if (!message) {
    elements.notice.hidden = true;
    elements.notice.textContent = "";
    elements.notice.classList.remove("is-info");
    return;
  }

  elements.notice.textContent = message;
  elements.notice.hidden = false;
  elements.notice.classList.toggle("is-info", type === "info");
}

function showScenarioPlaceholder() {
  elements.scenarioPreview.innerHTML = `
    <div class="preview-placeholder" aria-hidden="true">
      <span class="placeholder-line wide"></span>
      <span class="placeholder-line"></span>
      <span class="placeholder-line short"></span>
    </div>
  `;
}

function emptyInline(message) {
  return `<p class="empty-inline">${escapeHtml(message)}</p>`;
}

function formatDuration(milliseconds) {
  const value = Number(milliseconds);
  if (!Number.isFinite(value) || value <= 0) return "0 ms";
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toLocaleString("tr-TR", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 2,
  })} sn`;
}

function safeStringify(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return "kural";
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}
