const state = {
  user: null,
  repos: [],
  results: [],
  selectedRepoIds: new Set(),
  repoSearch: "",
  backgroundScanRunning: false,
  backgroundScanComplete: false,
  manualScanRunning: false,
  terminalQueue: {
    background: [],
    manual: [],
  },
  terminalFlushScheduled: {
    background: false,
    manual: false,
  },
};

const elements = {
  account: document.querySelector("#account"),
  loginPanel: document.querySelector("#login-panel"),
  appPanel: document.querySelector("#app-panel"),
  resultsPanel: document.querySelector("#results-panel"),
  repoSummary: document.querySelector("#repo-summary"),
  repoSearch: document.querySelector("#repo-search"),
  fileUrlInput: document.querySelector("#file-url-input"),
  cleanFileUrl: document.querySelector("#clean-file-url"),
  repoList: document.querySelector("#repo-list"),
  backgroundTerminal: document.querySelector("#background-terminal"),
  manualTerminal: document.querySelector("#manual-terminal"),
  manualTerminalShell: document.querySelector("#manual-terminal-shell"),
  status: document.querySelector("#status"),
  resultSummary: document.querySelector("#result-summary"),
  results: document.querySelector("#results"),
  selectAll: document.querySelector("#select-all"),
  scan: document.querySelector("#scan"),
  logout: document.querySelector("#logout"),
  selectFindings: document.querySelector("#select-findings"),
  cleanup: document.querySelector("#cleanup"),
};

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `Request failed: ${response.status}`);
  }

  return data;
}

function setStatus(message) {
  elements.status.textContent = message;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function encodeGitHubPath(path) {
  return path
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function findingUrl(repoResult, finding) {
  return `https://github.com/${repoResult.fullName}/blob/${encodeURIComponent(repoResult.branch)}/${encodeGitHubPath(finding.path)}`;
}

function findingsForRepo(repoResult) {
  return [...repoResult.infectedFiles, ...repoResult.batFiles];
}

function infectedResults() {
  return state.results.filter((repoResult) => findingsForRepo(repoResult).length > 0);
}

function totalInfectedRepos() {
  return infectedResults().length;
}

function totalsForCurrentResults() {
  return {
    repositories: state.results.length,
    scannedFiles: state.results.reduce((sum, item) => sum + item.scannedCount, 0),
    infectedFiles: state.results.reduce((sum, item) => sum + item.infectedFiles.length, 0),
    batFiles: state.results.reduce((sum, item) => sum + item.batFiles.length, 0),
    errors: state.results.reduce((sum, item) => sum + item.errors.length, 0),
  };
}

function mergeRepoResult(nextResult) {
  const existingIndex = state.results.findIndex(
    (item) => item.fullName === nextResult.fullName && item.branch === nextResult.branch,
  );

  if (existingIndex >= 0) {
    state.results[existingIndex] = nextResult;
  } else {
    state.results.push(nextResult);
  }
}

function terminalElement(context) {
  return context === "manual" ? elements.manualTerminal : elements.backgroundTerminal;
}

function showManualTerminal() {
  elements.manualTerminalShell.classList.remove("hidden");
}

function terminalLine(message, tone = "muted", context = "background") {
  state.terminalQueue[context].push({ message, tone, stamp: new Date().toLocaleTimeString() });

  if (!state.terminalFlushScheduled[context]) {
    state.terminalFlushScheduled[context] = true;
    requestAnimationFrame(() => flushTerminal(context));
  }
}

function flushTerminal(context) {
  const terminal = terminalElement(context);
  const fragment = document.createDocumentFragment();

  for (const item of state.terminalQueue[context].splice(0)) {
    const line = document.createElement("div");
    line.className = `terminal-line ${item.tone}`;
    line.textContent = `[${item.stamp}] ${item.message}`;
    fragment.append(line);
  }

  terminal.append(fragment);

  while (terminal.children.length > 1200) {
    terminal.firstElementChild.remove();
  }

  terminal.scrollTop = terminal.scrollHeight;
  state.terminalFlushScheduled[context] = false;

  if (state.terminalQueue[context].length > 0) {
    state.terminalFlushScheduled[context] = true;
    requestAnimationFrame(() => flushTerminal(context));
  }
}

function terminalLineImmediate(message, tone = "muted", context = "background") {
  const terminal = terminalElement(context);
  const line = document.createElement("div");
  line.className = `terminal-line ${tone}`;
  const stamp = new Date().toLocaleTimeString();
  line.textContent = `[${stamp}] ${message}`;
  terminal.append(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal(context = "background") {
  state.terminalQueue[context] = [];
  state.terminalFlushScheduled[context] = false;
  terminalElement(context).innerHTML = "";
}

function selectedRepos() {
  return [...state.selectedRepoIds]
    .map((id) => state.repos.find((item) => String(item.id) === id))
    .filter(Boolean)
    .map((repo) => ({
      owner: repo.owner,
      repo: repo.repo,
      defaultBranch: repo.defaultBranch,
      branch: repo.defaultBranch,
    }));
}

function allReposPayload() {
  return state.repos.map((repo) => ({
    owner: repo.owner,
    repo: repo.repo,
    defaultBranch: repo.defaultBranch,
    branch: repo.defaultBranch,
  }));
}

function selectedFindingIds() {
  return [...document.querySelectorAll(".finding-checkbox:checked")].map((input) => input.value);
}

function renderAccount() {
  if (!state.user) {
    elements.account.textContent = "";
    return;
  }

  elements.account.innerHTML = `
    <img src="${state.user.avatarUrl}" alt="" />
    <strong>${state.user.login}</strong>
  `;
}

function filteredRepos() {
  const query = state.repoSearch.trim().toLowerCase();
  const sourceRepos = state.backgroundScanComplete
    ? infectedResults()
        .map((repoResult) =>
          state.repos.find((repo) => repo.fullName === repoResult.fullName),
        )
        .filter(Boolean)
    : state.repos;

  if (!query) {
    return sourceRepos;
  }

  return sourceRepos.filter((repo) => {
    const haystack = [
      repo.fullName,
      repo.owner,
      repo.repo,
      repo.private ? "private" : "public",
      repo.defaultBranch,
      repo.permissions.push ? "writable" : "read only",
    ]
      .join(" ")
      .toLowerCase();

    return haystack.includes(query);
  });
}

function renderRepos() {
  const repos = filteredRepos();
  const infectedCount = totalInfectedRepos();
  elements.repoSummary.textContent = state.backgroundScanComplete
    ? `${infectedCount} infected repos / ${repos.length} shown / ${state.repos.length} accessible repositories`
    : `${repos.length} shown / ${state.repos.length} accessible repositories / ${state.selectedRepoIds.size} selected`;
  elements.repoList.innerHTML = repos
    .map(
      (repo) => `
        <label class="repo-row">
          <input
            class="repo-checkbox"
            type="checkbox"
            value="${repo.id}"
            ${state.selectedRepoIds.has(String(repo.id)) ? "checked" : ""}
          />
          <span>
            <span class="repo-name">${escapeHtml(repo.fullName)}</span>
            <span class="repo-meta">${repo.private ? "Private" : "Public"} / ${escapeHtml(repo.defaultBranch)}</span>
          </span>
          <span class="badge">${repo.permissions.push ? "Writable" : "Read only"}</span>
        </label>
      `,
    )
    .join("");
}

function renderResults(totals) {
  elements.resultsPanel.classList.remove("hidden");
  elements.resultSummary.textContent =
    `${totalInfectedRepos()} infected repos / ${totals.repositories} repositories / ${totals.scannedFiles} files scanned / ` +
    `${totals.infectedFiles} infected / ${totals.batFiles} .bat / ${totals.errors} errors`;

  const visibleResults = infectedResults().filter((repoResult) => {
    const query = state.repoSearch.trim().toLowerCase();
    if (!query) return true;
    return repoResult.fullName.toLowerCase().includes(query) || repoResult.branch.toLowerCase().includes(query);
  });

  if (visibleResults.length === 0) {
    elements.results.innerHTML = '<div class="empty-state">No infected repositories found.</div>';
    return;
  }

  elements.results.innerHTML = visibleResults
    .map((repoResult) => {
      const findings = findingsForRepo(repoResult);
      const statusClass =
        repoResult.errors.length > 0 ? "error" : findings.length > 0 ? "infected" : "clean";
      const statusText =
        repoResult.errors.length > 0 ? "Error" : findings.length > 0 ? "Needs cleanup" : "Clean";

      return `
        <article class="repo-result">
          <div class="repo-result-header">
            <div>
              <div class="repo-name">${escapeHtml(repoResult.fullName)}</div>
              <div class="repo-result-meta">
                ${escapeHtml(repoResult.branch)} / ${repoResult.scannedCount} files scanned /
                ${repoResult.skippedBinaryCount} binary skipped
                ${repoResult.truncated ? " / tree truncated" : ""}
              </div>
            </div>
            <span class="badge ${statusClass}">${statusText}</span>
          </div>
          <div class="repo-results">
            ${
              findings.length === 0
                ? '<div class="repo-meta">No infected files found.</div>'
                : findings
                    .map(
                      (finding) => `
                        <label class="finding-row">
                          <input class="finding-checkbox" type="checkbox" value="${finding.id}" />
                          <span>
                            <a class="finding-path" href="${findingUrl(repoResult, finding)}" target="_blank" rel="noreferrer">
                              ${escapeHtml(finding.path)}
                            </a>
                            <span class="finding-meta">
                              ${finding.action === "delete" ? ".bat file will be deleted" : `${finding.snippets} snippet(s) will be removed`}
                            </span>
                          </span>
                          <span class="badge ${finding.action === "delete" ? "error" : "infected"}">
                            ${finding.action === "delete" ? "Delete" : "Clean"}
                          </span>
                        </label>
                      `,
                    )
                    .join("")
            }
            ${
              repoResult.errors.length === 0
                ? ""
                : repoResult.errors
                    .map(
                      (error) => `
                        <div class="finding-row">
                          <span></span>
                          <span>
                            <span class="finding-path">${escapeHtml(error.path || repoResult.fullName)}</span>
                            <span class="finding-meta">${escapeHtml(error.message)}</span>
                          </span>
                          <span class="badge error">Error</span>
                        </div>
                      `,
                    )
                    .join("")
            }
          </div>
        </article>
      `;
    })
    .join("");
}

function handleScanEvent(event, context) {
  const label = context === "background" ? "bg" : "manual";
  const terminalContext = context === "manual" ? "manual" : "background";

  if (event.type === "start") {
    terminalLine(`${label} scan initialized for ${event.totalRepositories} repos`, "accent", terminalContext);
  }

  if (event.type === "repo:start") {
    terminalLine(`${label} cd ${event.repo.fullName} && git-ref ${event.repo.branch}`, "accent", terminalContext);
  }

  if (event.type === "file:scan") {
    terminalLine(`${label} scan ${event.repo.fullName}:${event.path}`, "muted", terminalContext);
  }

  if (event.type === "repo:complete") {
    mergeRepoResult(event.result);
    renderRepos();
    renderResults(totalsForCurrentResults());

    const findings = event.result.infectedFiles.length + event.result.batFiles.length;
    const tone = findings > 0 ? "warning" : "success";
    terminalLine(
      `${label} done ${event.repo.fullName} / files=${event.result.scannedCount} / findings=${findings} / errors=${event.result.errors.length}`,
      tone,
      terminalContext,
    );
  }

  if (event.type === "repo:error") {
    mergeRepoResult(event.result);
    renderRepos();
    renderResults(totalsForCurrentResults());
    terminalLine(`${label} error ${event.repo.fullName} / ${event.message}`, "danger", terminalContext);
  }

  if (event.type === "complete") {
    if (context === "background") {
      state.backgroundScanComplete = true;
      state.backgroundScanRunning = false;
      state.selectedRepoIds = new Set(
        infectedResults().map((repoResult) => {
          const repo = state.repos.find((item) => item.fullName === repoResult.fullName);
          return repo ? String(repo.id) : repoResult.fullName;
        }),
      );
      renderRepos();
    } else {
      state.manualScanRunning = false;
    }

    renderResults(totalsForCurrentResults());
    terminalLine(
      `${label} complete repos=${event.totals.repositories} infected_repos=${totalInfectedRepos()} files=${event.totals.scannedFiles} infected=${event.totals.infectedFiles} bat=${event.totals.batFiles} errors=${event.totals.errors}`,
      event.totals.infectedFiles + event.totals.batFiles > 0 ? "warning" : "success",
      terminalContext,
    );
  }

  if (event.type === "error") {
    if (context === "background") {
      state.backgroundScanRunning = false;
    } else {
      state.manualScanRunning = false;
    }
    terminalLine(`${label} error ${event.message}`, "danger", terminalContext);
  }
}

async function streamScan(repos, context) {
  const response = await fetch("/api/scan/stream", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ repos }),
  });

  if (!response.ok || !response.body) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || `Scan failed: ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      handleScanEvent(JSON.parse(line), context);
    }
  }

  if (buffer.trim()) {
    handleScanEvent(JSON.parse(buffer), context);
  }
}

async function loadSession() {
  try {
    state.user = await requestJson("/api/me");
    renderAccount();
    elements.loginPanel.classList.add("hidden");
    elements.appPanel.classList.remove("hidden");
    await loadRepos();
  } catch {
    elements.loginPanel.classList.remove("hidden");
    elements.appPanel.classList.add("hidden");
    elements.resultsPanel.classList.add("hidden");
  }
}

async function loadRepos() {
  setStatus("Loading repositories...");
  clearTerminal("background");
  clearTerminal("manual");
  terminalLineImmediate("awaiting github repository index...", "accent", "background");
  const data = await requestJson("/api/repos");
  state.repos = data.repos;
  state.selectedRepoIds = new Set();
  state.backgroundScanComplete = false;
  state.backgroundScanRunning = false;
  renderRepos();
  renderResults(totalsForCurrentResults());
  setStatus("Repository index loaded. Select repositories and run manual scan.");
  terminalLineImmediate(`indexed ${state.repos.length} accessible repositories`, "success", "background");
}

elements.selectAll.addEventListener("click", () => {
  const repos = filteredRepos();
  const shouldSelect = repos.some((repo) => !state.selectedRepoIds.has(String(repo.id)));

  repos.forEach((repo) => {
    if (shouldSelect) {
      state.selectedRepoIds.add(String(repo.id));
    } else {
      state.selectedRepoIds.delete(String(repo.id));
    }
  });

  renderRepos();
});

elements.repoSearch.addEventListener("input", (event) => {
  state.repoSearch = event.target.value;
  renderRepos();
  renderResults(totalsForCurrentResults());
});

elements.repoList.addEventListener("change", (event) => {
  if (!event.target.classList.contains("repo-checkbox")) return;

  if (event.target.checked) {
    state.selectedRepoIds.add(event.target.value);
  } else {
    state.selectedRepoIds.delete(event.target.value);
  }

  renderRepos();
});

async function runBackgroundScan() {
  if (state.backgroundScanRunning) {
    return;
  }

  state.backgroundScanRunning = true;
  state.backgroundScanComplete = false;
  const repos = allReposPayload();

  if (repos.length === 0) {
    state.backgroundScanRunning = false;
    terminalLine("bg scan aborted: no repositories available", "danger", "background");
    return;
  }

  terminalLine(`bg scanning ${repos.length} repositories`, "accent", "background");
  try {
    await streamScan(repos, "background");
    setStatus("Background scan complete.");
  } catch (error) {
    state.backgroundScanRunning = false;
    terminalLine(`bg fatal ${error.message}`, "danger", "background");
    setStatus(error.message);
  }
}

async function runManualScan(repos) {
  if (repos.length === 0) {
    setStatus("Select at least one repository.");
    terminalLine("manual scan aborted: no repositories selected", "danger", "manual");
    return;
  }

  if (state.manualScanRunning) {
    setStatus("Manual scan already running.");
    return;
  }

  state.manualScanRunning = true;
  showManualTerminal();
  clearTerminal("manual");
  elements.scan.disabled = true;
  setStatus(`Manual scan running for ${repos.length} repositories...`);
  terminalLine(`manual scanning ${repos.length} repositories`, "accent", "manual");

  try {
    await streamScan(repos, "manual");
    setStatus("Manual scan complete.");
  } catch (error) {
    state.manualScanRunning = false;
    setStatus(error.message);
    terminalLine(`manual fatal ${error.message}`, "danger", "manual");
  } finally {
    elements.scan.disabled = false;
  }
}

elements.scan.addEventListener("click", async () => {
  await runManualScan(selectedRepos());
});

elements.selectFindings.addEventListener("click", () => {
  const boxes = [...document.querySelectorAll(".finding-checkbox")];
  const shouldCheck = boxes.some((box) => !box.checked);
  boxes.forEach((box) => {
    box.checked = shouldCheck;
  });
});

elements.cleanup.addEventListener("click", async () => {
  const findingIds = selectedFindingIds();
  if (findingIds.length === 0) {
    setStatus("Select at least one finding to remove.");
    terminalLine("cleanup aborted: no findings selected", "danger", "background");
    return;
  }

  const confirmed = window.confirm(
    `Remove ${findingIds.length} selected finding(s)? This commits directly to the affected repository branches.`,
  );
  if (!confirmed) return;

  elements.cleanup.disabled = true;
  setStatus("Removing selected findings...");
  terminalLine(`cleanup requested for ${findingIds.length} findings`, "warning", "background");

  try {
    const data = await requestJson("/api/cleanup", {
      method: "POST",
      body: JSON.stringify({ findingIds }),
    });
    const cleanedIds = new Set(data.cleaned.filter((item) => item.cleaned).map((item) => item.id));
    state.results = state.results
      .map((repoResult) => ({
        ...repoResult,
        infectedFiles: repoResult.infectedFiles.filter((finding) => !cleanedIds.has(finding.id)),
        batFiles: repoResult.batFiles.filter((finding) => !cleanedIds.has(finding.id)),
      }))
      .filter((repoResult) => findingsForRepo(repoResult).length > 0 || repoResult.errors.length > 0);
    state.selectedRepoIds = new Set(infectedResults().map((repoResult) => {
      const repo = state.repos.find((item) => item.fullName === repoResult.fullName);
      return repo ? String(repo.id) : repoResult.fullName;
    }));
    setStatus(`Cleanup complete: ${data.totals.cleaned} cleaned, ${data.totals.errors} errors.`);
    terminalLine(`cleanup complete cleaned=${data.totals.cleaned} errors=${data.totals.errors}`, "success", "background");
    renderRepos();
    renderResults(totalsForCurrentResults());
  } catch (error) {
    setStatus(error.message);
    terminalLine(`cleanup failed ${error.message}`, "danger", "background");
  } finally {
    elements.cleanup.disabled = false;
  }
});

elements.cleanFileUrl.addEventListener("click", async () => {
  const fileUrl = elements.fileUrlInput.value.trim();
  if (!fileUrl) {
    setStatus("Paste a GitHub file link first.");
    terminalLine("clean-by-url aborted: empty input", "danger", "background");
    return;
  }

  elements.cleanFileUrl.disabled = true;
  setStatus("Cleaning file from URL...");
  terminalLine(`clean-by-url request ${fileUrl}`, "warning", "background");

  try {
    const data = await requestJson("/api/clean-by-url", {
      method: "POST",
      body: JSON.stringify({ fileUrl }),
    });

    if (!data.cleaned) {
      setStatus(data.message);
      terminalLine(`clean-by-url no change ${data.target.owner}/${data.target.repo}:${data.target.path}`, "warning", "background");
      return;
    }

    setStatus(`Cleaned ${data.target.path} (${data.snippetsRemoved} snippet(s) removed).`);
    terminalLine(
      `clean-by-url cleaned ${data.target.owner}/${data.target.repo}:${data.target.path} snippets=${data.snippetsRemoved}`,
      "success",
      "background",
    );
    elements.fileUrlInput.value = "";
  } catch (error) {
    setStatus(error.message);
    terminalLine(`clean-by-url failed ${error.message}`, "danger", "background");
  } finally {
    elements.cleanFileUrl.disabled = false;
  }
});

elements.logout.addEventListener("click", async () => {
  await requestJson("/auth/logout", { method: "POST" });
  window.location.reload();
});

loadSession();
