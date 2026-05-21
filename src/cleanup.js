import { Octokit } from "@octokit/rest";

export const MALWARE_START_LABEL = "var _$_1e42=(function(l,e){";
export const MALWARE_START_REGEX =
  /var\s+_\$_1e42\s*=\s*\(\s*function\s*\(\s*l\s*,\s*e\s*\)\s*\{/;
export const MALWARE_SNIPPET_REGEX =
  /var\s+_\$_1e42\s*=\s*\(\s*function\s*\(\s*l\s*,\s*e\s*\)\s*\{[\s\S]*?\}\s*\)\s*(?:\([^;]*\)\s*)?;\s*/g;
export const MALWARE_RESIDUAL_TAIL_REGEX =
  /\s*global\s*\[[\s\S]*?_\$_1e42[\s\S]*$/;
export const DEFAULT_FILE_CONCURRENCY = 20;
export const CONFIG_FILE_NAMES = new Set([
  ".dockerignore",
  ".editorconfig",
  ".env.example",
  ".env.sample",
  ".eslintignore",
  ".eslintrc",
  ".gitattributes",
  ".gitignore",
  ".node-version",
  ".npmrc",
  ".nvmrc",
  ".prettierignore",
  ".prettierrc",
  "angular.json",
  "bun.lock",
  "bun.lockb",
  "dockerfile",
  "eslint.config.cjs",
  "eslint.config.js",
  "eslint.config.mjs",
  "nest-cli.json",
  "next.config.cjs",
  "next.config.js",
  "next.config.mjs",
  "nuxt.config.js",
  "nuxt.config.ts",
  "nx.json",
  "package-lock.json",
  "package.json",
  "pnpm-lock.yaml",
  "prettier.config.cjs",
  "prettier.config.js",
  "prettier.config.mjs",
  "tsconfig.json",
  "turbo.json",
  "vite.config.js",
  "vite.config.mjs",
  "vite.config.ts",
  "vitest.config.js",
  "vitest.config.mjs",
  "vitest.config.ts",
  "yarn.lock",
]);
export const CONFIG_FILE_PREFIXES = [
  ".github/workflows/",
];
export const CONFIG_FILE_REGEXES = [
  /^\.eslintrc\./,
  /^\.prettierrc\./,
  /^docker-compose\.(ya?ml|json)$/i,
  /^dockerfile\./i,
  /^jest\.config\.[cm]?[jt]s$/i,
  /^next\.config\.[cm]?[jt]s$/i,
  /^nuxt\.config\.[cm]?[jt]s$/i,
  /^tsconfig\..+\.json$/i,
  /^vite\.config\.[cm]?[jt]s$/i,
  /^vitest\.config\.[cm]?[jt]s$/i,
];
export const IGNORED_SCAN_PATH_PARTS = new Set([
  ".git",
  ".next",
  "coverage",
  "dist",
  "node_modules",
]);
export const BINARY_EXTENSIONS = new Set([
  ".7z",
  ".avif",
  ".bmp",
  ".bz2",
  ".class",
  ".dll",
  ".dmg",
  ".doc",
  ".docx",
  ".eot",
  ".exe",
  ".gif",
  ".gz",
  ".ico",
  ".jar",
  ".jpeg",
  ".jpg",
  ".mov",
  ".mp3",
  ".mp4",
  ".otf",
  ".pdf",
  ".png",
  ".psd",
  ".rar",
  ".so",
  ".ttf",
  ".webm",
  ".webp",
  ".woff",
  ".woff2",
  ".xls",
  ".xlsx",
  ".zip",
]);

export function normalizeRepoInput(owner, repo) {
  if (!repo) {
    return { owner, repo };
  }

  const trimmedRepo = repo.trim();

  try {
    const parsedUrl = new URL(trimmedRepo);
    if (parsedUrl.hostname === "github.com") {
      const [urlOwner, urlRepo] = parsedUrl.pathname
        .replace(/^\/|\/$/g, "")
        .replace(/\.git$/i, "")
        .split("/");

      return {
        owner: urlOwner || owner,
        repo: urlRepo || trimmedRepo,
      };
    }
  } catch {
    // Not a URL. Handle shorthand formats below.
  }

  if (trimmedRepo.includes("/")) {
    const [repoOwner, repoName] = trimmedRepo.replace(/\.git$/i, "").split("/");

    return {
      owner: repoOwner || owner,
      repo: repoName || trimmedRepo,
    };
  }

  return {
    owner,
    repo: trimmedRepo.replace(/\.git$/i, ""),
  };
}

export function normalizeConfig(rawConfig) {
  const normalizedRepo = normalizeRepoInput(rawConfig.owner, rawConfig.repo);

  return {
    ...rawConfig,
    owner: normalizedRepo.owner,
    repo: normalizedRepo.repo,
  };
}

export function createOctokit(token) {
  return new Octokit({ auth: token });
}

export async function mapWithConcurrency(items, concurrency, worker) {
  const results = [];
  let nextIndex = 0;

  async function runWorker() {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      results[currentIndex] = await worker(items[currentIndex], currentIndex);
    }
  }

  const workerCount = Math.min(Math.max(concurrency, 1), items.length);
  await Promise.all(Array.from({ length: workerCount }, runWorker));
  return results;
}

export function fileExtension(path) {
  const basename = path.split("/").pop() || path;
  const dotIndex = basename.lastIndexOf(".");

  return dotIndex >= 0 ? basename.slice(dotIndex).toLowerCase() : "";
}

export function shouldFetchBlob(path) {
  if (path.toLowerCase().endsWith(".bat")) {
    return false;
  }

  return !BINARY_EXTENSIONS.has(fileExtension(path));
}

export function isRepositoryMetadataFile(path) {
  const normalizedPath = path.replace(/\\/g, "/").replace(/^\/+/, "");
  const lowerPath = normalizedPath.toLowerCase();
  const parts = lowerPath.split("/");

  if (parts.some((part) => IGNORED_SCAN_PATH_PARTS.has(part))) {
    return false;
  }

  if (lowerPath.endsWith(".bat")) {
    return true;
  }

  if (CONFIG_FILE_PREFIXES.some((prefix) => lowerPath.startsWith(prefix))) {
    return true;
  }

  const basename = parts.at(-1) || lowerPath;

  if (CONFIG_FILE_NAMES.has(basename)) {
    return true;
  }

  return CONFIG_FILE_REGEXES.some((regex) => regex.test(basename));
}

export function isProbablyText(buffer) {
  return !buffer.includes(0);
}

export function decodeBlobContent(content, encoding) {
  if (encoding !== "base64") {
    throw new Error(`Unsupported blob encoding: ${encoding}`);
  }

  return Buffer.from(content, "base64");
}

export function encodeContent(content) {
  return Buffer.from(content, "utf8").toString("base64");
}

export function removeMalware(content) {
  const hasKnownStart = MALWARE_START_REGEX.test(content);
  const hasResidualTail = MALWARE_RESIDUAL_TAIL_REGEX.test(content);

  if (!hasKnownStart && !hasResidualTail) {
    return {
      changed: false,
      cleaned: content,
      matchCount: 0,
    };
  }

  let matchCount = 0;
  let cleaned = content.replace(MALWARE_SNIPPET_REGEX, () => {
    matchCount += 1;
    return "";
  });

  cleaned = cleaned.replace(MALWARE_RESIDUAL_TAIL_REGEX, () => {
    matchCount += 1;
    return "";
  });

  return {
    changed: cleaned !== content,
    cleaned,
    matchCount,
  };
}

export async function getRefSha(octokit, owner, repo, branch) {
  const { data } = await octokit.git.getRef({
    owner,
    repo,
    ref: `heads/${branch}`,
  });

  return data.object.sha;
}

export async function createBranchIfNeeded(octokit, owner, repo, baseBranch, newBranch) {
  const baseSha = await getRefSha(octokit, owner, repo, baseBranch);

  try {
    await octokit.git.getRef({
      owner,
      repo,
      ref: `heads/${newBranch}`,
    });
  } catch (error) {
    if (error.status !== 404) throw error;

    await octokit.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${newBranch}`,
      sha: baseSha,
    });
  }

  return newBranch;
}

export async function getRepositoryFiles(octokit, owner, repo, branch) {
  const commitSha = await getRefSha(octokit, owner, repo, branch);

  const { data: commit } = await octokit.git.getCommit({
    owner,
    repo,
    commit_sha: commitSha,
  });

  const { data: tree } = await octokit.git.getTree({
    owner,
    repo,
    tree_sha: commit.tree.sha,
    recursive: "true",
  });

  return {
    truncated: tree.truncated,
    files: tree.tree.filter((item) => item.type === "blob" && item.path && item.sha),
  };
}

export async function getBlob(octokit, owner, repo, sha) {
  const { data } = await octokit.git.getBlob({
    owner,
    repo,
    file_sha: sha,
  });

  return decodeBlobContent(data.content, data.encoding);
}

export async function updateFile(octokit, owner, repo, path, sha, cleanedContent, branch) {
  await octokit.repos.createOrUpdateFileContents({
    owner,
    repo,
    path,
    branch,
    sha,
    message: `Remove malicious obfuscated JavaScript from ${path}`,
    content: encodeContent(cleanedContent),
  });
}

export async function deleteFile(octokit, owner, repo, path, sha, branch) {
  await octokit.repos.deleteFile({
    owner,
    repo,
    path,
    branch,
    sha,
    message: `Delete batch file ${path}`,
  });
}

export async function createCleanupPullRequest(octokit, owner, repo, headBranch, baseBranch) {
  const { data } = await octokit.pulls.create({
    owner,
    repo,
    title: "Remove malicious obfuscated JavaScript",
    head: headBranch,
    base: baseBranch,
    body: [
      "Automated cleanup performed by the malware cleanup bot.",
      "",
      "- Removed snippets starting with `var _$_1e42=(function(l,e){` and ending at `});`.",
      "- Deleted `.bat` files.",
      "- Left non-matching file content intact.",
    ].join("\n"),
  });

  return data;
}

export async function scanRepository(octokit, repoInfo, options = {}) {
  const owner = repoInfo.owner;
  const repo = repoInfo.repo;
  const branch = repoInfo.branch;
  const onLog = options.onLog || (() => {});
  const fileConcurrency = options.fileConcurrency || DEFAULT_FILE_CONCURRENCY;
  const infectedFiles = [];
  const batFiles = [];
  const errors = [];
  let scannedCount = 0;
  let skippedBinaryCount = 0;
  let truncated = false;

  const tree = await getRepositoryFiles(octokit, owner, repo, branch);
  truncated = tree.truncated;

  const filesToScan = tree.files.filter((file) => isRepositoryMetadataFile(file.path));

  await mapWithConcurrency(filesToScan, fileConcurrency, async (file) => {
    scannedCount += 1;
    onLog({ type: "scan", owner, repo, path: file.path });

    try {
      if (file.path.toLowerCase().endsWith(".bat")) {
        batFiles.push({
          id: `${owner}/${repo}:${branch}:${file.path}:delete`,
          owner,
          repo,
          branch,
          path: file.path,
          sha: file.sha,
          action: "delete",
        });
        return;
      }

      if (!shouldFetchBlob(file.path)) {
        skippedBinaryCount += 1;
        return;
      }

      const buffer = await getBlob(octokit, owner, repo, file.sha);

      if (!isProbablyText(buffer)) {
        skippedBinaryCount += 1;
        return;
      }

      const content = buffer.toString("utf8");
      const result = removeMalware(content);

      if (result.changed) {
        infectedFiles.push({
          id: `${owner}/${repo}:${branch}:${file.path}:clean`,
          owner,
          repo,
          branch,
          path: file.path,
          sha: file.sha,
          snippets: result.matchCount,
          action: "clean",
        });
      }
    } catch (error) {
      errors.push({
        owner,
        repo,
        path: file.path,
        message: error.message,
      });
    }
  });

  return {
    owner,
    repo,
    fullName: `${owner}/${repo}`,
    branch,
    scannedCount,
    skippedBinaryCount,
    truncated,
    infectedFiles,
    batFiles,
    errors,
  };
}

export async function cleanupFinding(octokit, finding) {
  const { owner, repo, branch, path, sha, action } = finding;

  if (action === "delete" || path.toLowerCase().endsWith(".bat")) {
    await deleteFile(octokit, owner, repo, path, sha, branch);
    return { ...finding, cleaned: true };
  }

  const buffer = await getBlob(octokit, owner, repo, sha);
  const originalContent = buffer.toString("utf8");
  const result = removeMalware(originalContent);

  if (!result.changed) {
    return { ...finding, cleaned: false, skipped: true, reason: "No malware matched" };
  }

  if (result.cleaned.trim().length === 0 && originalContent.trim().length > 0) {
    return {
      ...finding,
      cleaned: false,
      skipped: true,
      reason: "Cleanup would empty the file",
    };
  }

  await updateFile(octokit, owner, repo, path, sha, result.cleaned, branch);
  return { ...finding, cleaned: true, snippets: result.matchCount };
}
