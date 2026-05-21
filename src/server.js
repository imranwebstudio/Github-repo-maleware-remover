#!/usr/bin/env node

import "dotenv/config";

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";
import session from "express-session";
import createFileStore from "session-file-store";

import {
  cleanupFinding,
  createOctokit,
  encodeContent,
  mapWithConcurrency,
  removeMalware,
  scanRepository,
} from "./cleanup.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "..", "public");
const dataDir = path.join(__dirname, "..", ".data");
const runtimeDataDir = process.env.VERCEL ? "/tmp/github-malware-cleanup-bot" : dataDir;
const sessionDir = path.join(runtimeDataDir, "sessions");
const secretFile = path.join(runtimeDataDir, "session-secret");

const app = express();
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${port}`;
const clientId = process.env.GITHUB_CLIENT_ID;
const clientSecret = process.env.GITHUB_CLIENT_SECRET;
const oauthScopes = ["repo", "read:org"];
const scanRepoConcurrency = Number(process.env.SCAN_REPO_CONCURRENCY || 3);
const scanFileConcurrency = Number(process.env.SCAN_FILE_CONCURRENCY || 20);
const FileStore = createFileStore(session);

const scanCache = new Map();

function getSessionSecret() {
  if (process.env.SESSION_SECRET) {
    return process.env.SESSION_SECRET;
  }

  fs.mkdirSync(runtimeDataDir, { recursive: true });

  if (fs.existsSync(secretFile)) {
    return fs.readFileSync(secretFile, "utf8").trim();
  }

  const secret = crypto.randomBytes(48).toString("hex");
  fs.writeFileSync(secretFile, secret, { mode: 0o600 });
  return secret;
}

function requireOAuthConfig() {
  const missing = [];
  if (!clientId) missing.push("GITHUB_CLIENT_ID");
  if (!clientSecret) missing.push("GITHUB_CLIENT_SECRET");

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

function requireLogin(req, res, next) {
  if (!req.session.githubToken) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }

  next();
}

function getOctokit(req) {
  return createOctokit(req.session.githubToken);
}

function flattenFindings(scanResults) {
  return scanResults.flatMap((repoResult) => [
    ...repoResult.infectedFiles,
    ...repoResult.batFiles,
  ]);
}

function totalsForResults(results) {
  return {
    repositories: results.length,
    scannedFiles: results.reduce((sum, item) => sum + item.scannedCount, 0),
    infectedFiles: results.reduce((sum, item) => sum + item.infectedFiles.length, 0),
    batFiles: results.reduce((sum, item) => sum + item.batFiles.length, 0),
    errors: results.reduce((sum, item) => sum + item.errors.length, 0),
  };
}

function mergeScanResults(existingResults, newResults) {
  const merged = new Map();

  for (const result of existingResults) {
    merged.set(`${result.fullName}::${result.branch}`, result);
  }

  for (const result of newResults) {
    merged.set(`${result.fullName}::${result.branch}`, result);
  }

  return [...merged.values()];
}

function parseGitHubBlobUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (parsed.hostname !== "github.com") {
    throw new Error("Only github.com URLs are supported");
  }

  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 5 || parts[2] !== "blob") {
    throw new Error("Expected format: https://github.com/<owner>/<repo>/blob/<branch>/<path>");
  }

  return {
    owner: parts[0],
    repo: parts[1],
    branch: parts[3],
    path: parts.slice(4).join("/"),
  };
}

function friendlyGitHubError(error, fallback = "GitHub API request failed.") {
  if (!error || typeof error !== "object") {
    return fallback;
  }

  if (error.status === 403) {
    return "GitHub returned 403 for this file. Your OAuth token likely lacks access to this repository, or the organization requires SSO authorization for the token.";
  }

  if (error.status === 404) {
    return "GitHub returned 404. The repository, branch, or file path in the URL was not found, or your token cannot see that private repo.";
  }

  if (typeof error.message === "string" && error.message.trim()) {
    return error.message;
  }

  return fallback;
}

app.use(express.json({ limit: "1mb" }));
app.use(
  session({
    name: "malware-cleanup.sid",
    secret: getSessionSecret(),
    store: new FileStore({
      path: sessionDir,
      retries: 1,
      ttl: 60 * 60 * 24 * 14,
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: appBaseUrl.startsWith("https://"),
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  }),
);
app.use(express.static(publicDir));

app.get("/auth/github", (req, res) => {
  requireOAuthConfig();

  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;

  const authorizeUrl = new URL("https://github.com/login/oauth/authorize");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", `${appBaseUrl}/auth/github/callback`);
  authorizeUrl.searchParams.set("scope", oauthScopes.join(" "));
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("allow_signup", "true");

  res.redirect(authorizeUrl.toString());
});

app.get("/auth/github/callback", async (req, res, next) => {
  try {
    requireOAuthConfig();

    if (!req.query.code || req.query.state !== req.session.oauthState) {
      res.status(400).send("Invalid OAuth callback.");
      return;
    }

    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code: req.query.code,
        redirect_uri: `${appBaseUrl}/auth/github/callback`,
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error(`GitHub token exchange failed: ${tokenResponse.status}`);
    }

    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      throw new Error(tokenData.error_description || "GitHub did not return an access token");
    }

    req.session.githubToken = tokenData.access_token;
    req.session.oauthState = null;
    scanCache.delete(req.session.id);

    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

app.post("/auth/logout", (req, res) => {
  scanCache.delete(req.session.id);
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/me", requireLogin, async (req, res, next) => {
  try {
    const octokit = getOctokit(req);
    const { data } = await octokit.users.getAuthenticated();

    res.json({
      login: data.login,
      name: data.name,
      avatarUrl: data.avatar_url,
      htmlUrl: data.html_url,
      scopes: oauthScopes,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/repos", requireLogin, async (req, res, next) => {
  try {
    const octokit = getOctokit(req);
    const repos = await octokit.paginate(octokit.repos.listForAuthenticatedUser, {
      visibility: "all",
      affiliation: "owner,collaborator,organization_member",
      sort: "updated",
      per_page: 100,
    });

    res.json({
      repos: repos.map((repo) => ({
        id: repo.id,
        fullName: repo.full_name,
        owner: repo.owner.login,
        repo: repo.name,
        private: repo.private,
        defaultBranch: repo.default_branch,
        permissions: repo.permissions || {},
        htmlUrl: repo.html_url,
      })),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/scan/stream", requireLogin, async (req, res) => {
  const octokit = getOctokit(req);
  const selectedRepos = Array.isArray(req.body.repos) ? req.body.repos : [];

  res.writeHead(200, {
    "content-type": "application/x-ndjson; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });

  const send = (event) => {
    res.write(`${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`);
  };

  if (selectedRepos.length === 0) {
    send({ type: "error", message: "Select at least one repository to scan." });
    res.end();
    return;
  }

  const results = [];
  send({ type: "start", totalRepositories: selectedRepos.length });

  await mapWithConcurrency(selectedRepos, scanRepoConcurrency, async (repo) => {
    if (res.destroyed) return;

    const repoRef = {
      owner: repo.owner,
      repo: repo.repo,
      branch: repo.branch || repo.defaultBranch,
      fullName: `${repo.owner}/${repo.repo}`,
    };

    send({ type: "repo:start", repo: repoRef });

    try {
      const result = await scanRepository(octokit, repoRef, {
        fileConcurrency: scanFileConcurrency,
        onLog: (entry) => {
          send({
            type: "file:scan",
            repo: repoRef,
            path: entry.path,
          });
        },
      });

      results.push(result);
      send({
        type: "repo:complete",
        repo: repoRef,
        result,
      });
    } catch (error) {
      const result = {
        owner: repo.owner,
        repo: repo.repo,
        fullName: `${repo.owner}/${repo.repo}`,
        branch: repo.branch || repo.defaultBranch,
        scannedCount: 0,
        skippedBinaryCount: 0,
        truncated: false,
        infectedFiles: [],
        batFiles: [],
        errors: [{ owner: repo.owner, repo: repo.repo, path: "", message: error.message }],
      };
      results.push(result);
      send({
        type: "repo:error",
        repo: repoRef,
        result,
        message: error.message,
      });
    }
  });

  const existingResults = scanCache.get(req.session.id) || [];
  const mergedResults = mergeScanResults(existingResults, results);
  scanCache.set(req.session.id, mergedResults);
  send({
    type: "complete",
    results: mergedResults,
    totals: totalsForResults(mergedResults),
  });
  res.end();
});

app.post("/api/scan", requireLogin, async (req, res, next) => {
  try {
    const octokit = getOctokit(req);
    const selectedRepos = Array.isArray(req.body.repos) ? req.body.repos : [];

    if (selectedRepos.length === 0) {
      res.status(400).json({ error: "Select at least one repository to scan." });
      return;
    }

    const results = [];

    await mapWithConcurrency(selectedRepos, scanRepoConcurrency, async (repo) => {
      try {
        const result = await scanRepository(octokit, {
          owner: repo.owner,
          repo: repo.repo,
          branch: repo.branch || repo.defaultBranch,
        }, {
          fileConcurrency: scanFileConcurrency,
        });
        results.push(result);
      } catch (error) {
        results.push({
          owner: repo.owner,
          repo: repo.repo,
          fullName: `${repo.owner}/${repo.repo}`,
          branch: repo.branch || repo.defaultBranch,
          scannedCount: 0,
          skippedBinaryCount: 0,
          truncated: false,
          infectedFiles: [],
          batFiles: [],
          errors: [{ owner: repo.owner, repo: repo.repo, path: "", message: error.message }],
        });
      }
    });

    const existingResults = scanCache.get(req.session.id) || [];
    const mergedResults = mergeScanResults(existingResults, results);
    scanCache.set(req.session.id, mergedResults);

    res.json({
      results: mergedResults,
      totals: totalsForResults(mergedResults),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/cleanup", requireLogin, async (req, res, next) => {
  try {
    const octokit = getOctokit(req);
    const cachedResults = scanCache.get(req.session.id) || [];
    const allFindings = flattenFindings(cachedResults);
    const requestedIds = new Set(Array.isArray(req.body.findingIds) ? req.body.findingIds : []);
    const findings =
      requestedIds.size > 0
        ? allFindings.filter((finding) => requestedIds.has(finding.id))
        : allFindings;

    if (findings.length === 0) {
      res.status(400).json({ error: "No findings selected for cleanup." });
      return;
    }

    const cleaned = [];
    const errors = [];

    for (const finding of findings) {
      try {
        cleaned.push(await cleanupFinding(octokit, finding));
      } catch (error) {
        errors.push({ finding, message: error.message });
      }
    }

    const cleanedIds = new Set(cleaned.filter((item) => item.cleaned).map((item) => item.id));
    const remainingResults = cachedResults
      .map((repoResult) => ({
        ...repoResult,
        infectedFiles: repoResult.infectedFiles.filter((finding) => !cleanedIds.has(finding.id)),
        batFiles: repoResult.batFiles.filter((finding) => !cleanedIds.has(finding.id)),
      }))
      .filter(
        (repoResult) =>
          repoResult.infectedFiles.length > 0 ||
          repoResult.batFiles.length > 0 ||
          repoResult.errors.length > 0,
      );
    scanCache.set(req.session.id, remainingResults);

    res.json({
      cleaned,
      errors,
      totals: {
        requested: findings.length,
        cleaned: cleaned.filter((item) => item.cleaned).length,
        errors: errors.length,
      },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/clean-by-url", requireLogin, async (req, res, next) => {
  try {
    const octokit = getOctokit(req);
    const fileUrl = String(req.body.fileUrl || "").trim();
    if (!fileUrl) {
      res.status(400).json({ error: "fileUrl is required." });
      return;
    }

    const target = parseGitHubBlobUrl(fileUrl);

    const { data } = await octokit.repos.getContent({
      owner: target.owner,
      repo: target.repo,
      path: target.path,
      ref: target.branch,
    });

    if (Array.isArray(data) || data.type !== "file") {
      res.status(400).json({ error: "URL must point to a file." });
      return;
    }

    const originalContent = Buffer.from(data.content, "base64").toString("utf8");
    const result = removeMalware(originalContent);

    if (!result.changed) {
      res.json({
        cleaned: false,
        message: "No obfuscated malware snippet matched in this file.",
        target,
      });
      return;
    }

    if (result.cleaned.trim().length === 0 && originalContent.trim().length > 0) {
      res.status(400).json({ error: "Refusing to empty file after cleanup." });
      return;
    }

    await octokit.repos.createOrUpdateFileContents({
      owner: target.owner,
      repo: target.repo,
      path: target.path,
      branch: target.branch,
      sha: data.sha,
      message: `Remove malicious obfuscated JavaScript from ${target.path}`,
      content: encodeContent(result.cleaned),
    });

    res.json({
      cleaned: true,
      message: "File cleaned and committed.",
      snippetsRemoved: result.matchCount,
      target,
    });
  } catch (error) {
    res.status(error?.status || 500).json({
      error: friendlyGitHubError(error, "Unable to clean file from URL."),
    });
  }
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  res.status(500).json({ error: error.message });
});

export default app;

if (!process.env.VERCEL && import.meta.url === `file://${process.argv[1]}`) {
  requireOAuthConfig();
  const server = app.listen(port, host, () => {
    console.log(`[web] Listening on ${appBaseUrl}`);
  });

  server.on("error", (error) => {
    if (error.code === "EADDRINUSE") {
      console.error(`[web] Port ${port} is already in use.`);
      console.error(`[web] Start on another port with: PORT=3001 APP_BASE_URL=http://localhost:3001 npm run web`);
      console.error(`[web] Your GitHub OAuth callback must match: http://localhost:3001/auth/github/callback`);
      process.exit(1);
    }

    throw error;
  });
}
