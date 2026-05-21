#!/usr/bin/env node

import "dotenv/config";

import {
  cleanupFinding,
  createCleanupPullRequest,
  createBranchIfNeeded,
  createOctokit,
  normalizeConfig,
  scanRepository,
} from "./cleanup.js";

const config = normalizeConfig({
  token: process.env.GITHUB_PAT,
  owner: process.env.GITHUB_OWNER,
  repo: process.env.GITHUB_REPO,
  branch: process.env.GITHUB_BRANCH || "main",
  createPr: process.env.CREATE_PR === "true",
  dryRun: process.env.DRY_RUN === "true",
  prBranch:
    process.env.PR_BRANCH ||
    `malware-cleanup-${new Date().toISOString().replace(/[:.]/g, "-")}`,
});

function log(message) {
  console.log(`[cleanup] ${message}`);
}

function requireConfig() {
  const missing = [];

  if (!config.token) missing.push("GITHUB_PAT");
  if (!config.owner) missing.push("GITHUB_OWNER");
  if (!config.repo) missing.push("GITHUB_REPO");

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

async function main() {
  requireConfig();

  const octokit = createOctokit(config.token);
  const targetBranch = config.createPr
    ? await createBranchIfNeeded(
        octokit,
        config.owner,
        config.repo,
        config.branch,
        config.prBranch,
      )
    : config.branch;

  log(`Repository: ${config.owner}/${config.repo}`);
  log(`Base branch: ${config.branch}`);
  log(`Working branch: ${targetBranch}`);
  if (config.dryRun) {
    log("Dry run: enabled. Files will be scanned but not changed.");
  }

  const result = await scanRepository(
    octokit,
    {
      owner: config.owner,
      repo: config.repo,
      branch: targetBranch,
    },
    {
      onLog: (entry) => {
        log(`Scanned: ${entry.path}`);
      },
    },
  );

  if (result.truncated) {
    log("WARNING: Git tree response was truncated; some files may not be scanned.");
  }

  const findings = [...result.infectedFiles, ...result.batFiles];
  let cleanedCount = 0;
  let deletedBatCount = 0;

  for (const finding of findings) {
    if (finding.action === "delete") {
      log(`.bat file found: ${finding.path}`);
    } else {
      log(`Malicious code found: ${finding.path} (${finding.snippets} snippet(s))`);
    }

    if (config.dryRun) {
      if (finding.action === "delete") {
        deletedBatCount += 1;
        log(`Would delete: ${finding.path}`);
      } else {
        cleanedCount += 1;
        log(`Would clean: ${finding.path}`);
      }
      continue;
    }

    const cleanupResult = await cleanupFinding(octokit, finding);
    if (cleanupResult.cleaned && finding.action === "delete") {
      deletedBatCount += 1;
      log(`Deleted: ${finding.path}`);
    } else if (cleanupResult.cleaned) {
      cleanedCount += 1;
      log(`Cleaned: ${finding.path}`);
    } else {
      log(`Skipped: ${finding.path} (${cleanupResult.reason || "unchanged"})`);
    }
  }

  if (config.createPr && !config.dryRun && (cleanedCount > 0 || deletedBatCount > 0)) {
    const pullRequest = await createCleanupPullRequest(
      octokit,
      config.owner,
      config.repo,
      targetBranch,
      config.branch,
    );
    log(`Created pull request: ${pullRequest.html_url}`);
  }

  log("Cleanup complete");
  log(`Files scanned: ${result.scannedCount}`);
  log(`Files with malicious code: ${result.infectedFiles.length}`);
  log(`Files cleaned: ${cleanedCount}`);
  log(`.bat files deleted: ${deletedBatCount}`);
  log(`Binary files skipped: ${result.skippedBinaryCount}`);
  log(`Errors: ${result.errors.length}`);

  for (const error of result.errors) {
    log(`ERROR processing ${error.path}: ${error.message}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(`[cleanup] Fatal error: ${error.message}`);
    process.exit(1);
  });
}
