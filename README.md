# GitHub Malware Cleanup Bot

Node.js CLI bot that scans a GitHub repository branch, removes the malicious obfuscated JavaScript snippet that starts with:

```js
var _$_1e42=(function(l,e){
```

and deletes any `.bat` files it finds.

## Setup

```bash
npm install
cp .env.example .env
```

Edit `.env`:

```bash
GITHUB_PAT=ghp_your_token
GITHUB_OWNER=your-org-or-user
GITHUB_REPO=your-repo
GITHUB_BRANCH=main
CREATE_PR=false
DRY_RUN=false
```

`GITHUB_REPO` can be only the repo name, `owner/repo`, or a GitHub URL. For example, these all work:

```bash
GITHUB_OWNER=Softvence-Omega-Cyber-Monk
GITHUB_REPO=cahyonoahmad-dashboard-app
```

```bash
GITHUB_REPO=Softvence-Omega-Cyber-Monk/cahyonoahmad-dashboard-app
```

```bash
GITHUB_REPO=https://github.com/Softvence-Omega-Cyber-Monk/cahyonoahmad-dashboard-app.git
```

The GitHub token needs permission to read repository contents and write contents. For private repositories, it also needs repository access.

## Run

Commit directly to the configured branch:

```bash
npm start
```

Create a pull request instead:

```bash
CREATE_PR=true npm start
```

Scan without changing files:

```bash
DRY_RUN=true npm start
```

## Web UI

Create a GitHub OAuth App:

- Homepage URL: `http://localhost:3000`
- Authorization callback URL: `http://localhost:3000/auth/github/callback`

Add the OAuth values to `.env`:

```bash
GITHUB_CLIENT_ID=your_oauth_client_id
GITHUB_CLIENT_SECRET=your_oauth_client_secret
SESSION_SECRET=replace_with_a_long_random_string
APP_BASE_URL=http://localhost:3000
PORT=3000
```

Start the graphical interface:

```bash
npm run web
```

Open `http://localhost:3000`, login with GitHub, select repositories, scan them, and remove selected findings.

If port `3000` is already in use, use another port and make the OAuth callback URL match:

```bash
PORT=3001 APP_BASE_URL=http://localhost:3001 npm run web
```

Callback URL:

```text
http://localhost:3001/auth/github/callback
```

The web app requests `repo read:org` scopes. Organization repositories appear only when the authenticated user has access and the organization allows this OAuth app. Some organizations require SSO authorization before private org repositories can be scanned or cleaned.

Login sessions persist across server restarts. Session files are stored under `.data/sessions`, and `.data` is ignored by git. If `SESSION_SECRET` is not set, the app generates and stores one at `.data/session-secret`.

For faster scans, tune bounded concurrency:

```bash
SCAN_REPO_CONCURRENCY=3
SCAN_FILE_CONCURRENCY=8
```

Higher values can be faster, but GitHub may throttle aggressive scans.

## Safety Behavior

- Scans every blob in the target branch tree.
- Logs every scanned file.
- Skips binary files.
- Removes only matching malicious snippets.
- Refuses to update a file if cleanup would unexpectedly empty a previously non-empty file.
- Deletes `.bat` files.
- Logs per-file errors and continues scanning.

## Important

Do not hardcode your GitHub PAT in source files. Put it in `.env` or pass it as an environment variable.
