"use strict";

const $ = (id) => document.getElementById(id);

function formatTime(epoch) {
  if (epoch === null || epoch === undefined) return "-";
  return new Date(epoch * 1000).toLocaleString("zh-CN", { hour12: false });
}

async function fetchJSON(url, options) {
  const response = await fetch(url, options || {});
  let payload = null;
  try {
    payload = await response.json();
  } catch (err) {
    payload = null;
  }
  if (!response.ok) {
    const message = payload && payload.detail && payload.detail.message
      ? payload.detail.message
      : `请求失败（HTTP ${response.status}）`;
    throw new Error(message);
  }
  return payload;
}

function renderStatus(data) {
  $("rtr-endpoint").textContent = `${data.rtr_source.host}:${data.rtr_source.port}`;
  const sync = data.sync;
  $("sync-state").textContent =
    sync.state === "syncing"
      ? `同步中…（第 ${sync.attempts} 次）`
      : `空闲（已尝试 ${sync.attempts} 次）`;

  const version = data.version;
  if (version) {
    $("version-info").textContent =
      `v${version.version_id} · 会话 ${version.session_id} · 序号 ${version.serial}`;
    $("version-expiry").textContent =
      `${formatTime(version.expires_at)}${version.expired ? "（已过期）" : ""}`;
    $("version-count").textContent = `${version.roa_count} 条`;
  } else {
    $("version-info").textContent = "无（尚未成功同步）";
    $("version-expiry").textContent = "-";
    $("version-count").textContent = "-";
  }

  $("query-available").textContent = data.query_available ? "可核对" : "无法核对";
  $("query-available").className = data.query_available ? "ok" : "warn";
  $("sync-message").textContent = data.message +
    (sync.last_error ? `；上次错误：${sync.last_error}` : "");
  $("sync-button").disabled = sync.state === "syncing";
  $("sync-button").textContent =
    sync.state === "syncing" ? "同步进行中…" : "手动同步全量授权";
}

async function refreshStatus() {
  try {
    renderStatus(await fetchJSON("/api/status"));
  } catch (err) {
    $("sync-message").textContent = `状态获取失败：${err.message}`;
  }
}

function stateClass(state) {
  if (state === "Valid") return "state-valid";
  if (state === "Invalid") return "state-invalid";
  if (state === "NotFound") return "state-notfound";
  return "state-unavailable";
}

function renderValidation(data) {
  const box = $("validate-result");
  const message = $("validate-message");
  message.textContent = "";

  if (!data.available) {
    box.classList.add("hidden");
    message.textContent = data.message;
    return;
  }

  const rows = data.covering.length
    ? data.covering.map((item) => `
      <tr>
        <td>${item.prefix}</td>
        <td>AS${item.asn}</td>
        <td>${item.max_length}</td>
        <td>${item.asn_matches ? "是" : "否"}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" class="muted">无覆盖授权</td></tr>`;

  box.className = `result ${stateClass(data.state)}`;
  box.innerHTML = `
    <div class="state-badge">${data.state}</div>
    <p class="reason">${data.reason}</p>
    <p class="muted">核对对象：${data.prefix} · 起源 AS${data.asn}</p>
    <table>
      <thead>
        <tr><th>覆盖授权前缀</th><th>授权 ASN</th><th>maxLength</th><th>ASN 匹配</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="muted">依据版本：v${data.version.version_id} ·
       会话 ${data.version.session_id} · 序号 ${data.version.serial} ·
       到期 ${formatTime(data.version.expires_at)}</p>`;
}

$("sync-button").addEventListener("click", async () => {
  const message = $("sync-message");
  try {
    const data = await fetchJSON("/api/sync", { method: "POST" });
    message.textContent = data.message;
  } catch (err) {
    message.textContent = err.message;
  }
  refreshStatus();
});

$("validate-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = $("validate-message");
  message.textContent = "核对中…";
  try {
    const data = await fetchJSON("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prefix: $("prefix-input").value,
        asn: $("asn-input").value,
      }),
    });
    renderValidation(data);
  } catch (err) {
    $("validate-result").classList.add("hidden");
    message.textContent = err.message;
  }
});

refreshStatus();
setInterval(refreshStatus, 3000);
