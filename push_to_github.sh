#!/data/data/com.termux/files/usr/bin/bash
# ══════════════════════════════════════════════════════════════════
# CTF - Push to GitHub → GitHub Actions builds the APK
# ══════════════════════════════════════════════════════════════════

# NO set -e - we check every command explicitly so nothing is silent
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TMPJSON="${TMPDIR:-/data/data/com.termux/files/usr/tmp}/gh_api.json"

# ── helpers ────────────────────────────────────────────────────────
step()  { echo ""; echo "──────────────────────────────────────"; echo "[$1/6] $2"; echo "──────────────────────────────────────"; }
ok()    { echo "    ✓ $1"; }
fail()  { echo ""; echo "  ✗ FAILED: $1"; echo "  FIX:    $2"; echo ""; exit 1; }
warn()  { echo "  ! $1"; }

# ── pre-flight ─────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════"
echo "  Connect the Felons → GitHub Build"
echo "══════════════════════════════════════"

step 1 "Pre-flight checks"

# git
if ! command -v git &>/dev/null; then
    echo "    git not found, installing..."
    pkg install -y git
    command -v git &>/dev/null || fail "git install failed" "Run: pkg install git"
fi
ok "git: $(git --version)"

# curl
command -v curl &>/dev/null || fail "curl not found" "Run: pkg install curl"
ok "curl: $(curl --version | head -1)"

# workflow file
if [ ! -f ".github/workflows/build.yml" ]; then
    fail ".github/workflows/build.yml missing" \
         "Re-extract the ZIP: unzip -o ConnectTheFelons.zip"
fi
ok ".github/workflows/build.yml present"

# ── gather credentials ─────────────────────────────────────────────
step 2 "GitHub credentials"
echo ""
echo "  You need a Personal Access Token (PAT)."
echo "  Get one at: github.com → Settings → Developer settings"
echo "              → Personal access tokens → Tokens (classic)"
echo "              → Generate new token → check: repo"
echo ""

read -r -p "  GitHub username:  " GITHUB_USER
[ -z "$GITHUB_USER" ] && fail "Username cannot be empty" "Re-run and enter your GitHub username"

read -r -p "  Repo name [connect-the-felons]: " REPO_NAME
REPO_NAME="${REPO_NAME:-connect-the-felons}"

read -r -s -p "  Personal Access Token: " GITHUB_TOKEN
echo ""
[ -z "$GITHUB_TOKEN" ] && fail "Token cannot be empty" "Re-run and enter your PAT"

# ── verify token against GitHub API ───────────────────────────────
step 3 "Verify token"

HTTP=$(curl -s -o "$TMPJSON" -w "%{http_code}" \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/user" 2>&1)
CURL_EXIT=$?

if [ "$CURL_EXIT" != "0" ]; then
    fail "curl failed (exit $CURL_EXIT)" "Check network: curl https://api.github.com/user"
fi
if [ "$HTTP" != "200" ]; then
    echo "    GitHub API response (HTTP $HTTP):"
    cat "$TMPJSON"
    echo ""
    if [ "$HTTP" = "401" ]; then
        fail "Token rejected (HTTP 401)" "Generate a new PAT at github.com → Settings → Developer settings"
    else
        fail "GitHub API returned HTTP $HTTP" "Check your token and username"
    fi
fi
VERIFIED_USER=$(grep -o '"login":"[^"]*"' "$TMPJSON" | head -1 | cut -d'"' -f4)
ok "Authenticated as: $VERIFIED_USER"

# ── create repo ────────────────────────────────────────────────────
step 4 "Create GitHub repo"

HTTP=$(curl -s -o "$TMPJSON" -w "%{http_code}" \
    -X POST \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/user/repos" \
    -d "{\"name\":\"${REPO_NAME}\",\"private\":true,\"description\":\"Connect the Felons OSINT forensic platform\"}" 2>&1)
CURL_EXIT=$?

if [ "$CURL_EXIT" != "0" ]; then
    fail "curl failed creating repo (exit $CURL_EXIT)" "Check network connection"
fi

if [ "$HTTP" = "201" ]; then
    ok "Repo created: https://github.com/${GITHUB_USER}/${REPO_NAME}"
elif [ "$HTTP" = "422" ]; then
    warn "Repo already exists - will push to it"
    ok "https://github.com/${GITHUB_USER}/${REPO_NAME}"
else
    echo "    GitHub API response (HTTP $HTTP):"
    cat "$TMPJSON"
    echo ""
    fail "Could not create repo (HTTP $HTTP)" "Check token has 'repo' scope"
fi

# ── git init, commit, push ─────────────────────────────────────────
step 5 "Commit and push"

REPO_URL="https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/${GITHUB_USER}/${REPO_NAME}.git"

# Init if needed
if [ ! -d ".git" ]; then
    echo "    Initializing git..."
    git init || fail "git init failed" "Check disk space: df -h ."
    ok "git init"
fi

# Set identity (--local so it only affects this repo, no global config needed)
git config --local user.email "ctf@build.local"
git config --local user.name  "CTF Builder"
ok "git identity set"

# Set remote (remove old one first in case of re-run with wrong token)
git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL" || fail "git remote add failed" "This is a bug, report it"

# Stage everything
git add -A
ok "Files staged: $(git diff --cached --name-only | wc -l | tr -d ' ') files"

# Commit (allow re-runs: if nothing new just continue)
if git diff --cached --quiet; then
    warn "Nothing new to commit (already committed)"
else
    git commit -m "CTF build $(date +%Y-%m-%d)" \
        || fail "git commit failed" "Check git status: git status"
    ok "Committed"
fi

# Push (--force handles re-runs where remote already has a different history)
echo "    Pushing to GitHub..."
git push --force -u origin main \
    || { git push --force -u origin master 2>/dev/null \
         || fail "git push failed" \
                 "Run: git push --force -u origin main  and paste the full error"; }
ok "Pushed to GitHub"

# Remove token from remote URL (don't leave PAT in .git/config)
git remote set-url origin "https://github.com/${GITHUB_USER}/${REPO_NAME}.git"
ok "PAT removed from git config"

# ── summary ────────────────────────────────────────────────────────
step 6 "Done"
echo ""
echo "  GitHub Actions is building your APK now."
echo "  First build: ~5 minutes"
echo ""
echo "  ╔════════════════════════════════════════╗"
echo "  ║  WATCH BUILD:                          ║"
echo "  ║  github.com/${GITHUB_USER}/${REPO_NAME}"
echo "  ║  → Actions tab                         ║"
echo "  ╠════════════════════════════════════════╣"
echo "  ║  GET APK (when green ✓):               ║"
echo "  ║  Click the workflow run                ║"
echo "  ║  → scroll to Artifacts                 ║"
echo "  ║  → download CTF-debug-N.zip            ║"
echo "  ║  → unzip → tap app-debug.apk           ║"
echo "  ║  → Settings → allow install → Install  ║"
echo "  ╚════════════════════════════════════════╝"
echo ""
