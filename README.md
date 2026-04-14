# npm postinstall attack scanner

[日本語](#日本語) | [English](#english)

---

## 日本語

npmサプライチェーン攻撃（**postinstall + 偽依存関係パターン**）を検出するスキャナー。

[axios メンテナーアカウント乗っ取り事件（2026-03-31）](https://x.com/riku720720/status/2038976598914019546)をきっかけに作成。

### 攻撃パターン

1. 攻撃者がnpmメンテナーのアカウントを乗っ取り（メール変更等でpublish権限を掌握）
2. `package.json`に**偽の依存関係を追加**して新バージョンを公開（ソースコード自体は変更なし）
3. 偽パッケージの**postinstallスクリプト**が実行され：
   - C&Cサーバーに接続
   - プラットフォーム別のRAT（Remote Access Trojan）をダウンロード・実行
   - 自分自身を削除して痕跡を隠蔽
4. `^`（キャレット）指定で`npm install`/`npm update`すると自動的に感染

**なぜ検出が難しいか**: パッケージ本体のソースコードは完全にクリーン。悪意は間接依存のinstallスクリプトに隠れている。

**亜種パターン（2026-04-03 `mgc`）**: 偽依存ではなく、パッケージ自体のpostinstallスクリプトがGitHub Gistからプラットフォーム別ペイロードをダウンロード・実行し、C2サーバーに接続する。

### 導入方法

```bash
# リポジトリをクローン
git clone https://github.com/aliksir/npm-postinstall-attack-scanner.git
cd npm-postinstall-attack-scanner

# または、スクリプトだけダウンロード
curl -sL https://raw.githubusercontent.com/aliksir/npm-postinstall-attack-scanner/master/scan.sh -o scan.sh
```

必要なもの: `bash` と `npm`（Node.jsプロジェクトがあれば入っているはず）

### 使い方

```bash
# カレントディレクトリをスキャン
bash scan.sh .

# 特定プロジェクトをスキャン
bash scan.sh /path/to/your/project

# ワークスペース全体をスキャン
bash scan.sh /path/to/workspace
```

問題が見つかれば対策手順が自動表示されます。

### チェック内容（5フェーズ）

| フェーズ | 内容 | 方法 |
|---------|------|------|
| 1 | **既知の侵害バージョン** | lockfile + node_modules内のバージョン照合 |
| 2 | **悪意ある依存パッケージ** | 既知のマルウェアパッケージ名を検索（例: `plain-crypto-js`） |
| 3 | **不審なpostinstallスクリプト** | eval/exec/ネットワーク呼び出しのパターンマッチ |
| 4 | **危険なバージョン範囲** | 攻撃対象パッケージの `^`/`~` 範囲指定を検出 |
| 5 | **npmキャッシュ** | キャッシュ内の侵害パッケージ残留を検出 |
| 6 | **C2ドメイン/ペイロードホスト** | 既知のC2・GitHub Gistペイロードホストをスクリプト内から検出 |

### 出力例

クリーンなプロジェクトの場合:
```
=== npm postinstall attack scanner ===
[Phase 1] Known compromised version check
  [OK] Known compromised versions not found
[Phase 2] Malicious dependency check
  [OK] Known malicious dependencies not found
[Phase 3] Suspicious postinstall script detection
  [OK] No suspicious postinstall scripts detected
[Phase 4] Dangerous version range check
  [OK] No dangerous version ranges on known-targeted packages
[Phase 5] npm cache check
  [OK] No compromised packages in npm cache
=== Scan Summary ===
No issues found. Project appears clean.
```

終了コード: `0` = 問題なし、`1` = 問題あり

### GitHub Actionsで使う

リポジトリの `.github/workflows/scan.yml` に追加:

```yaml
name: npm postinstall attack scan

on:
  push:
    paths: ['package.json', 'package-lock.json']
  pull_request:
    paths: ['package.json', 'package-lock.json']
  schedule:
    - cron: '0 9 * * *'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download scanner
        run: curl -sL https://raw.githubusercontent.com/aliksir/npm-postinstall-attack-scanner/main/scan.sh -o /tmp/scan.sh
      - name: Run scan
        run: bash /tmp/scan.sh .
```

### 既知の侵害パッケージ

| パッケージ | バージョン | 悪意ある依存/手法 | 発生日 | C&C |
|-----------|-----------|------------------|--------|-----|
| axios | 1.14.1 | plain-crypto-js@^4.2.1 | 2026-03-31 | sfrclak.com:8000 |
| axios | 0.30.4 | plain-crypto-js@^4.2.1 | 2026-03-31 | sfrclak.com:8000 |
| mgc | 1.2.1-1.2.4 | 自身のpostinstall（GitHub Gistペイロード） | 2026-04-03 | admondtamang.com.np |

### 新しい攻撃が発覚したら

`scan.sh` の配列に追記するだけ:

```bash
KNOWN_COMPROMISED=(
  # ... 既存エントリ ...
  "new-package@bad-version|malicious-dep|説明"
)

KNOWN_MALICIOUS_DEPS=(
  # ... 既存エントリ ...
  "malicious-dep"
)
```

### 侵害が検出された場合の対応

1. **安全なバージョンに固定**: `npm install axios@1.15.0`
2. **node_modules再構築**: `rm -rf node_modules package-lock.json && npm install`
3. **npmキャッシュクリア**: `npm cache clean --force`
4. **シークレットのローテーション**（RAT実行の可能性がある場合）: APIキー、トークン、SSH鍵、DB認証情報、ウォレット秘密鍵
5. **RAT痕跡の確認**: 不審なプロセス、スケジュールタスク/cron、スタートアップ登録

### 予防策

- 依存バージョンをピン留め（`"1.15.0"` であって `"^1.15.0"` ではなく）
- npm 2FAを有効化（ハードウェアキー推奨）
- CI/CDでは `npm ci` を使用（lockfileの整合性チェック）
- `.npmrc` に `min-release-age=7` を設定
- [Trusted Publisher](https://docs.npmjs.com/generating-provenance-statements)（GitHub OIDC）を活用

### Claude Code連携

このスキャナーは [Claude Code](https://claude.ai/claude-code) のスキルとしても使えます。`claude-code/` ディレクトリを `~/.claude/skills/npm-postinstall-attack-scanner/` にコピーすれば、`/npm-postinstall-attack-scanner` で呼び出せます。

### 免責事項

- 本ツールは**既知のパターンに基づく簡易検出ツール**です。全ての攻撃の検出を保証するものではありません。
- `npm audit` / `osv-scanner` / `trivy` 等の他のセキュリティツールとの併用を推奨します。
- 本ツールの使用により生じた損害について、作者は一切の責任を負いません。
- 既知の侵害パッケージDBは最新でない場合があります。公式情報と併せてご確認ください。

---

## English

Detects npm supply chain attacks that use the **postinstall + hidden dependency** pattern to deliver malware.

Built in response to the [axios maintainer account takeover (2026-03-31)](https://x.com/riku720720/status/2038976598914019546).

### The Attack Pattern

1. Attacker takes over an npm maintainer account (email change, credential theft)
2. Publishes a new version with a **malicious dependency** added to `package.json` (source code is untouched)
3. The malicious dependency runs a **postinstall script** that:
   - Contacts a C&C server
   - Downloads a platform-specific RAT (Remote Access Trojan)
   - Self-deletes to hide evidence
4. Anyone running `npm install` or `npm update` with `^` version ranges gets infected

**Why it's hard to detect**: The package source code is completely clean. The malice is hidden in a transitive dependency's install script.

**Variant pattern (2026-04-03 `mgc`)**: Instead of a fake dependency, the package's own postinstall script downloads platform-specific payloads from GitHub Gists and connects to a C2 server.

### Installation

```bash
# Clone the repo
git clone https://github.com/aliksir/npm-postinstall-attack-scanner.git
cd npm-postinstall-attack-scanner

# Or just download the script
curl -sL https://raw.githubusercontent.com/aliksir/npm-postinstall-attack-scanner/master/scan.sh -o scan.sh
```

Requirements: `bash` and `npm` (you already have these if you work with Node.js)

### Quick Start

```bash
# Scan current directory
bash scan.sh .

# Scan a specific project
bash scan.sh /path/to/your/project

# Scan all projects
bash scan.sh /path/to/workspace
```

If issues are found, remediation steps are displayed automatically.

### What It Checks (5 Phases)

| Phase | What | How |
|-------|------|-----|
| 1 | **Known compromised versions** | Checks lockfile + node_modules for exact version matches |
| 2 | **Malicious dependencies** | Searches for known malware packages (e.g., `plain-crypto-js`) |
| 3 | **Suspicious postinstall scripts** | Pattern-matches for eval/exec/network calls in install scripts |
| 4 | **Dangerous version ranges** | Detects `^`/`~` ranges on targeted packages |
| 5 | **npm cache** | Checks if compromised packages are cached locally |
| 6 | **C2 domain / payload host** | Detects known C2 domains and GitHub Gist payload hosts in scripts |

### Output

Clean project:
```
=== npm postinstall attack scanner ===
[Phase 1] Known compromised version check
  [OK] Known compromised versions not found
[Phase 2] Malicious dependency check
  [OK] Known malicious dependencies not found
[Phase 3] Suspicious postinstall script detection
  [OK] No suspicious postinstall scripts detected
[Phase 4] Dangerous version range check
  [OK] No dangerous version ranges on known-targeted packages
[Phase 5] npm cache check
  [OK] No compromised packages in npm cache
=== Scan Summary ===
No issues found. Project appears clean.
```

Exit codes: `0` = clean, `1` = issues found.

### GitHub Actions

Add to your repo's `.github/workflows/scan.yml`:

```yaml
name: npm postinstall attack scan

on:
  push:
    paths: ['package.json', 'package-lock.json']
  pull_request:
    paths: ['package.json', 'package-lock.json']
  schedule:
    - cron: '0 9 * * *'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download scanner
        run: curl -sL https://raw.githubusercontent.com/aliksir/npm-postinstall-attack-scanner/main/scan.sh -o /tmp/scan.sh
      - name: Run scan
        run: bash /tmp/scan.sh .
```

### Known Compromised Packages

| Package | Version | Malicious Dep / Method | Date | C&C |
|---------|---------|----------------------|------|-----|
| axios | 1.14.1 | plain-crypto-js@^4.2.1 | 2026-03-31 | sfrclak.com:8000 |
| axios | 0.30.4 | plain-crypto-js@^4.2.1 | 2026-03-31 | sfrclak.com:8000 |
| mgc | 1.2.1-1.2.4 | Self postinstall (GitHub Gist payload) | 2026-04-03 | admondtamang.com.np |

### Adding New Entries

When a new attack is discovered, edit `scan.sh` and add to the arrays:

```bash
KNOWN_COMPROMISED=(
  # ... existing entries ...
  "new-package@bad-version|malicious-dep|description"
)

KNOWN_MALICIOUS_DEPS=(
  # ... existing entries ...
  "malicious-dep"
)
```

### Remediation

If compromised packages are found:

1. **Pin to safe version**: `npm install axios@1.15.0`
2. **Rebuild**: `rm -rf node_modules package-lock.json && npm install`
3. **Clear cache**: `npm cache clean --force`
4. **Rotate secrets** (if RAT may have executed): API keys, tokens, SSH keys, DB credentials, wallet keys
5. **Check for RAT artifacts**: unexpected processes, new scheduled tasks, modified startup files

### Prevention

- Pin dependency versions exactly (`"1.15.0"`, not `"^1.15.0"`)
- Enable npm 2FA with hardware key
- Use `npm ci` in CI/CD (lockfile integrity check)
- Add `min-release-age=7` to `.npmrc`
- Use [Trusted Publisher](https://docs.npmjs.com/generating-provenance-statements) (GitHub OIDC)

### Claude Code Integration

This scanner is also available as a [Claude Code](https://claude.ai/claude-code) skill. Copy the `claude-code/` directory to `~/.claude/skills/npm-postinstall-attack-scanner/` to use it with `/npm-postinstall-attack-scanner`.

## Disclaimer / 免責事項

- This tool detects **known patterns only**. It does not guarantee detection of all supply chain attacks.
- Always use in combination with other security tools (`npm audit`, `osv-scanner`, `trivy`, etc.).
- The author assumes no liability for any damages resulting from the use of this tool.
- The known compromised packages database may not be up to date. Always verify with official sources.

---

- 本ツールは**既知のパターンに基づく簡易検出ツール**です。全ての攻撃の検出を保証するものではありません。
- `npm audit` / `osv-scanner` / `trivy` 等の他のセキュリティツールとの併用を推奨します。
- 本ツールの使用により生じた損害について、作者は一切の責任を負いません。
- 既知の侵害パッケージDBは最新でない場合があります。公式情報と併せてご確認ください。

## License

MIT
