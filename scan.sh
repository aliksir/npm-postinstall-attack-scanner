#!/usr/bin/env bash
# npm postinstall attack scanner
# Detects compromised packages using the postinstall + hidden dependency pattern
# (e.g., axios@1.14.1/0.30.4 supply chain attack, 2026-03-31)
# (e.g., mgc@1.2.1-1.2.4 Axios variant with GitHub-hosted payloads, 2026-04-03)
#
# Usage: bash scan.sh [target-directory]
# Exit codes: 0 = clean, 1 = issues found

set -euo pipefail

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  YELLOW='\033[1;33m'
  GREEN='\033[0;32m'
  CYAN='\033[0;36m'
  NC='\033[0m'
else
  RED='' YELLOW='' GREEN='' CYAN='' NC=''
fi

TARGET_DIR="${1:-.}"
FOUND_ISSUES=0

echo -e "${CYAN}=== npm postinstall attack scanner ===${NC}"
echo "Target: $TARGET_DIR"
echo "Date: $(date '+%Y-%m-%d %H:%M')"
echo ""

# ============================================================
# Known Compromised Packages DB
# ============================================================
# Format: "package@version|malicious_dependency|description"
# Add new entries here when new attacks are discovered
KNOWN_COMPROMISED=(
  "axios@1.14.1|plain-crypto-js|axios maintainer account takeover (2026-03-31)"
  "axios@0.30.4|plain-crypto-js|axios maintainer account takeover (2026-03-31)"
  "mgc@1.2.1|mgc|Axios variant: GitHub-hosted payload + C2 admondtamang.com.np (2026-04-03)"
  "mgc@1.2.2|mgc|Axios variant: GitHub-hosted payload + C2 admondtamang.com.np (2026-04-03)"
  "mgc@1.2.3|mgc|Axios variant: GitHub-hosted payload + C2 admondtamang.com.np (2026-04-03)"
  "mgc@1.2.4|mgc|Axios variant: GitHub-hosted payload + C2 admondtamang.com.np (2026-04-03)"
)

# Known malicious packages (dependency side)
KNOWN_MALICIOUS_DEPS=(
  "plain-crypto-js"
  "mgc"
)

# Known C2 domains / payload hosts
KNOWN_C2_DOMAINS=(
  "sfrclak.com"
  "admondtamang.com.np"
)

KNOWN_PAYLOAD_HOSTS=(
  "gist.githubusercontent.com/admondtamang"
)

# ============================================================
# Phase 1: Check known compromised versions
# ============================================================
echo -e "${CYAN}[Phase 1] Known compromised version check${NC}"

PHASE1_ISSUES=0

while IFS= read -r lockfile; do
  for entry in "${KNOWN_COMPROMISED[@]}"; do
    pkg_ver="${entry%%|*}"
    rest="${entry#*|}"
    mal_dep="${rest%%|*}"
    desc="${rest#*|}"
    pkg="${pkg_ver%%@*}"
    ver="${pkg_ver#*@}"

    if grep -q "\"$pkg\"" "$lockfile" 2>/dev/null; then
      if grep -q "\"version\": \"$ver\"" "$lockfile" 2>/dev/null; then
        echo -e "  ${RED}[CRITICAL] $lockfile: $pkg@$ver detected!${NC}"
        echo -e "  ${RED}  -> $desc${NC}"
        echo -e "  ${RED}  -> Malicious dependency: $mal_dep${NC}"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
        PHASE1_ISSUES=$((PHASE1_ISSUES + 1))
      fi
    fi
  done
done < <(find "$TARGET_DIR" -name "package-lock.json" -not -path "*/node_modules/*" -not -path "*/_deleted/*" 2>/dev/null)

# Also check node_modules directly
for entry in "${KNOWN_COMPROMISED[@]}"; do
  pkg_ver="${entry%%|*}"
  pkg="${pkg_ver%%@*}"
  ver="${pkg_ver#*@}"

  while IFS= read -r nm_pkg; do
    installed_ver=$(grep -o '"version": "[^"]*"' "$nm_pkg" 2>/dev/null | head -1 | sed 's/"version": "//;s/"//')
    if [[ "$installed_ver" == "$ver" ]]; then
      echo -e "  ${RED}[CRITICAL] $nm_pkg: installed version is $ver!${NC}"
      FOUND_ISSUES=$((FOUND_ISSUES + 1))
      PHASE1_ISSUES=$((PHASE1_ISSUES + 1))
    fi
  done < <(find "$TARGET_DIR" -path "*/node_modules/$pkg/package.json" 2>/dev/null)
done

if [[ $PHASE1_ISSUES -eq 0 ]]; then
  echo -e "  ${GREEN}[OK] Known compromised versions not found${NC}"
fi

# ============================================================
# Phase 2: Check for known malicious dependencies
# ============================================================
echo ""
echo -e "${CYAN}[Phase 2] Malicious dependency check${NC}"

PHASE2_ISSUES=0
for mal_dep in "${KNOWN_MALICIOUS_DEPS[@]}"; do
  while IFS= read -r lockfile; do
    if grep -q "\"$mal_dep\"" "$lockfile" 2>/dev/null; then
      echo -e "  ${RED}[CRITICAL] $lockfile: malicious dependency '$mal_dep' found!${NC}"
      FOUND_ISSUES=$((FOUND_ISSUES + 1))
      PHASE2_ISSUES=$((PHASE2_ISSUES + 1))
    fi
  done < <(find "$TARGET_DIR" -name "package-lock.json" -not -path "*/node_modules/*" -not -path "*/_deleted/*" 2>/dev/null)

  while IFS= read -r mal_dir; do
    echo -e "  ${RED}[CRITICAL] $mal_dir: malicious package installed!${NC}"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
    PHASE2_ISSUES=$((PHASE2_ISSUES + 1))
  done < <(find "$TARGET_DIR" -type d -name "$mal_dep" -path "*/node_modules/*" 2>/dev/null)
done

if [[ $PHASE2_ISSUES -eq 0 ]]; then
  echo -e "  ${GREEN}[OK] Known malicious dependencies not found${NC}"
fi

# ============================================================
# Phase 3: Suspicious postinstall script detection
# ============================================================
echo ""
echo -e "${CYAN}[Phase 3] Suspicious postinstall script detection${NC}"

PHASE3_ISSUES=0

while IFS= read -r pjson; do
  if grep -qE '"(postinstall|preinstall)"' "$pjson" 2>/dev/null; then
    local_dir=$(dirname "$pjson")
    pkg_name=$(grep -o '"name": "[^"]*"' "$pjson" 2>/dev/null | head -1 | sed 's/"name": "//;s/"//')

    while IFS= read -r script_line; do
      script_ref=$(echo "$script_line" | sed 's/.*": "//;s/".*//' | tr -d '[:space:]')
      if [[ "$script_ref" == *".js"* ]]; then
        script_file="$local_dir/$script_ref"
        if [[ -f "$script_file" ]]; then
          if grep -qiE '(eval\(|new Function|child_process|\.connect\(|net\.Socket|http\.request|https\.request|Buffer\.from.*base64|\\x[0-9a-f]{2}|String\.fromCharCode|execSync|spawnSync|gist\.githubusercontent\.com)' "$script_file" 2>/dev/null; then
            echo -e "  ${YELLOW}[WARN] $pkg_name: suspicious postinstall script${NC}"
            echo -e "  ${YELLOW}  -> File: $script_file${NC}"
            match=$(grep -m1 -iE '(eval\(|new Function|child_process|\.connect\(|net\.Socket|http\.request|Buffer\.from.*base64|execSync|spawnSync)' "$script_file" 2>/dev/null | head -c 120)
            echo -e "  ${YELLOW}  -> Match: $match${NC}"
            PHASE3_ISSUES=$((PHASE3_ISSUES + 1))
            FOUND_ISSUES=$((FOUND_ISSUES + 1))
          fi
        fi
      fi
    done < <(grep -E '"(postinstall|preinstall)"' "$pjson" 2>/dev/null)
  fi
done < <(find "$TARGET_DIR" -path "*/node_modules/*/package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null | head -500)

if [[ $PHASE3_ISSUES -eq 0 ]]; then
  echo -e "  ${GREEN}[OK] No suspicious postinstall scripts detected${NC}"
fi

# ============================================================
# Phase 4: Version range vulnerability check
# ============================================================
echo ""
echo -e "${CYAN}[Phase 4] Dangerous version range check${NC}"

PHASE4_ISSUES=0
while IFS= read -r pjson; do
  for entry in "${KNOWN_COMPROMISED[@]}"; do
    pkg_ver="${entry%%|*}"
    pkg="${pkg_ver%%@*}"

    if grep -qE "\"$pkg\"[[:space:]]*:[[:space:]]*\"[\^~]" "$pjson" 2>/dev/null; then
      range=$(grep -o "\"$pkg\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$pjson" 2>/dev/null)
      echo -e "  ${YELLOW}[WARN] $pjson: $pkg uses floating range: $range${NC}"
      echo -e "  ${YELLOW}  -> Pin to exact version to prevent auto-upgrade to compromised version${NC}"
      PHASE4_ISSUES=$((PHASE4_ISSUES + 1))
      FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi
  done
done < <(find "$TARGET_DIR" -name "package.json" -not -path "*/node_modules/*" -not -path "*/_deleted/*" 2>/dev/null)

if [[ $PHASE4_ISSUES -eq 0 ]]; then
  echo -e "  ${GREEN}[OK] No dangerous version ranges on known-targeted packages${NC}"
fi

# ============================================================
# Phase 5: npm cache check
# ============================================================
echo ""
echo -e "${CYAN}[Phase 5] npm cache check${NC}"

NPM_CACHE=$(npm config get cache 2>/dev/null || echo "")
PHASE5_ISSUES=0
if [[ -n "$NPM_CACHE" ]] && [[ -d "$NPM_CACHE" ]]; then
  for entry in "${KNOWN_COMPROMISED[@]}"; do
    pkg_ver="${entry%%|*}"
    pkg="${pkg_ver%%@*}"
    ver="${pkg_ver#*@}"
    if find "$NPM_CACHE" -name "${pkg}-${ver}.tgz" 2>/dev/null | grep -q .; then
      echo -e "  ${RED}[CRITICAL] Compromised package in npm cache: $pkg@$ver${NC}"
      echo -e "  ${RED}  -> Run: npm cache clean --force${NC}"
      PHASE5_ISSUES=$((PHASE5_ISSUES + 1))
      FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi
  done
  if [[ $PHASE5_ISSUES -eq 0 ]]; then
    echo -e "  ${GREEN}[OK] No compromised packages in npm cache${NC}"
  fi
else
  echo -e "  ${YELLOW}[SKIP] npm cache directory not accessible${NC}"
fi

# ============================================================
# Phase 6: C2 domain / payload host detection in scripts
# ============================================================
echo ""
echo -e "${CYAN}[Phase 6] C2 domain / payload host detection${NC}"

PHASE6_ISSUES=0
while IFS= read -r pjson || [[ -n "$pjson" ]]; do
  [[ -z "$pjson" ]] && continue
  local_dir=$(dirname "$pjson")
  pkg_name=$(grep -o '"name": "[^"]*"' "$pjson" 2>/dev/null | head -1 | sed 's/"name": "//;s/"//' || true)
  [[ -z "$pkg_name" ]] && pkg_name="(unknown)"

  # Check all .js files in the package directory (not subdirectories)
  while IFS= read -r jsfile || [[ -n "$jsfile" ]]; do
    [[ -z "$jsfile" ]] && continue
    for c2 in "${KNOWN_C2_DOMAINS[@]}"; do
      if grep -q "$c2" "$jsfile" 2>/dev/null; then
        echo -e "  ${RED}[CRITICAL] $pkg_name: C2 domain '$c2' found in $jsfile${NC}"
        match=$(grep -m1 "$c2" "$jsfile" 2>/dev/null | head -c 120)
        echo -e "  ${RED}  -> Match: $match${NC}"
        PHASE6_ISSUES=$((PHASE6_ISSUES + 1))
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
      fi
    done
    for host in "${KNOWN_PAYLOAD_HOSTS[@]}"; do
      if grep -q "$host" "$jsfile" 2>/dev/null; then
        echo -e "  ${RED}[CRITICAL] $pkg_name: payload host '$host' found in $jsfile${NC}"
        match=$(grep -m1 "$host" "$jsfile" 2>/dev/null | head -c 120)
        echo -e "  ${RED}  -> Match: $match${NC}"
        PHASE6_ISSUES=$((PHASE6_ISSUES + 1))
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
      fi
    done
  done < <(find "$local_dir" -maxdepth 1 -name "*.js" 2>/dev/null || true)
done < <(find "$TARGET_DIR" -path "*/node_modules/*/package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null | head -500)

if [[ $PHASE6_ISSUES -eq 0 ]]; then
  echo -e "  ${GREEN}[OK] No known C2 domains or payload hosts detected${NC}"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${CYAN}=== Scan Summary ===${NC}"
if [[ $FOUND_ISSUES -gt 0 ]]; then
  echo -e "${RED}Found $FOUND_ISSUES issue(s)!${NC}"
  echo ""
  echo -e "${YELLOW}=== Remediation Steps ===${NC}"
  echo "1. Remove/pin affected packages:"
  echo "   npm install axios@1.14.0   # or axios@0.30.3"
  echo "   npm uninstall mgc          # if installed"
  echo ""
  echo "2. Rebuild node_modules:"
  echo "   rm -rf node_modules package-lock.json && npm install"
  echo ""
  echo "3. Clear npm cache:"
  echo "   npm cache clean --force"
  echo ""
  echo "4. If RAT may have executed, rotate ALL secrets:"
  echo "   - API keys, tokens, SSH keys"
  echo "   - Database credentials"
  echo "   - Wallet private keys"
  echo "   - npm/GitHub tokens"
  echo ""
  echo "5. Check for RAT artifacts:"
  echo "   - Unexpected processes (Task Manager / ps aux)"
  echo "   - New scheduled tasks / cron jobs"
  echo "   - Modified startup files (~/.bashrc, Registry Run keys)"
  exit 1
else
  echo -e "${GREEN}No issues found. Project appears clean.${NC}"
  echo ""
  echo "Preventive recommendations:"
  echo "  - Pin dependency versions exactly (no ^ or ~)"
  echo "  - Enable npm 2FA with hardware key"
  echo "  - Use 'npm ci' in CI/CD (lockfile integrity check)"
  echo "  - Set 'min-release-age=7' in .npmrc"
  echo "  - Run this scanner periodically"
  exit 0
fi
