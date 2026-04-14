---
name: npm-postinstall-attack-scanner
description: Detect npm supply chain attacks using the postinstall + hidden dependency pattern. Covers axios takeover (2026-03-31) and similar attacks.
---

# npm postinstall attack scanner

Detects npm supply chain attacks where a maintainer account is compromised, a malicious dependency is added to package.json, and the dependency's postinstall script delivers malware (RAT).

## Trigger

Keywords: "npm supply chain", "npm attack", "postinstall attack", "axios takeover", "compromised package", "npm security check", "supply chain attack"

## Usage

Run the scanner on any directory containing Node.js projects:

```bash
bash scan.sh [target-directory]
```

The script checks 5 phases:
1. Known compromised versions (lockfile + node_modules)
2. Known malicious dependency packages
3. Suspicious postinstall scripts (pattern matching)
4. Dangerous version ranges on targeted packages
5. npm cache for compromised packages

## Remediation

If issues are found:
1. Pin to safe version: `npm install axios@1.15.0`
2. Rebuild: `rm -rf node_modules package-lock.json && npm install`
3. Clear cache: `npm cache clean --force`
4. Rotate all secrets if RAT may have executed
5. Check for RAT artifacts (processes, scheduled tasks, startup files)

## Known Compromised Packages

| Package | Version | Malicious Dep | Date |
|---------|---------|---------------|------|
| axios | 1.14.1 | plain-crypto-js@^4.2.1 | 2026-03-31 |
| axios | 0.30.4 | plain-crypto-js@^4.2.1 | 2026-03-31 |

## More Info

See the full README at: https://github.com/aliksir/npm-postinstall-attack-scanner
