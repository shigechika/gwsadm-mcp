<!-- mcp-name: io.github.shigechika/gwsadm-mcp -->

# gwsadm-mcp

[English](README.md) | 日本語

Google Workspace の**セキュリティ監査**用 MCP（Model Context Protocol）サーバ。
アカウントロック・不審なログイン・外部へのファイル共有への読み取り専用の
可視性を提供する。Admin SDK Reports API（監査アクティビティ）をベースに構築。

管理コンソールの視点にちなんで `gwsadm`（= Google Workspace admin）と命名。
[`boxadm-mcp`](https://github.com/shigechika/boxadm-mcp) の姉妹サーバ。
汎用的な Workspace MCP では**ない**： リスクを可視化するだけで、何も変更しない。

## 機能

| ツール | 説明 |
|------|------|
| `health_check` | サーバーバージョン・設定パス・ドメインごとの認証確認 — セッション開始時やタイムアウト後に呼ぶ |
| `login_audit` | Reports API `login` — **Google により自動無効化されたアカウント**（`account_disabled_*`： 漏洩パスワード・乗っ取り・スパム送信）、不審なログイン、失敗の多い順トップN |
| `drive_external_sharing` | Reports API `drive` — 外部アドレス/ドメインへの ACL **付与**（取り消しは別集計）、リンク公開/一般公開への可視性**遷移** |
| `daily_brief` | 設定済み全ドメインを横断した一括サマリ |

計画中： `dlp_events`（Reports `rules`、DLP 対応の Workspace エディションが必要）、
`suspended_accounts`（Directory API スナップショット、
`admin.directory.user.readonly` の DWD スコープが必要）、`token_events`、`admin_events`。

## 認証方式

監査権限を持つ管理者になりすます、**ドメイン単位の委任（DWD）**付きサービスアカウント。
完全に非対話式 — ブラウザ操作もトークンのリフレッシュローテーションも不要なので、
無人実行できる（cron・MCP ゲートウェイ・CI）。

サービスアカウントのクライアント ID ごとに必要な DWD スコープ:

```
https://www.googleapis.com/auth/admin.reports.audit.readonly
```

## セットアップ

```bash
# uv
uv pip install gwsadm-mcp

# pip
pip install gwsadm-mcp
```

またはソースから:

```bash
git clone https://github.com/shigechika/gwsadm-mcp.git
cd gwsadm-mcp

# uv
uv sync

# pip
pip install -e .
```

## 設定

`GWSADM_CONFIG` で INI ファイルを指定する（既定値は `~/.config/gwsadm-mcp/config.ini`、
パーミッションは `0600` にする）:

```ini
[gwsadm]
# 省略可。省略時は全 [domain.*] セクション名が対象になる
internal_domains = example.edu, mail.example.edu

[domain.example.edu]
service_account_file = /path/to/service-account.json
subject = audit-admin@example.edu
customer_id = C0xxxxxxx
```

監査対象の Workspace ドメインごとに1つの `[domain.*]` セクションを置く。
`internal_domains` は共有先を内部/外部に分類するための許可リスト。

## 使い方

### Claude Code

`.mcp.json` に追加する（設定ファイルが既定パスにある場合は `env` 不要。
既定以外のパスの場合のみ `"env": { "GWSADM_CONFIG": "..." }` を追加）:

```json
{
  "mcpServers": {
    "gwsadm-mcp": {
      "type": "stdio",
      "command": "gwsadm-mcp"
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json` に同じエントリを追加する。

### 直接実行

```bash
gwsadm-mcp
```

### CLI オプション

```bash
gwsadm-mcp --version   # バージョンを表示して終了
gwsadm-mcp --check     # 全ドメインの設定・認証・API 疎通を検証して終了
gwsadm-mcp             # MCP サーバを起動（STDIO、既定）
```

`--check` の終了コード: 成功時 `0`、設定または認証失敗時は非ゼロ。

## 補足

- 各結果セクションは、ウィンドウがページ予算を超えた場合やプローブの取得自体が
  エラーになった場合（`event_errors` 参照）に `capped: true` を返す —
  部分的な結果を「該当なし」として提示することはない。Drive スキャンは
  どの eventName が打ち切られたかを `capped_events` にも記録する。
  網羅的な結果が必要な場合は `hours` を狭めるか `max_pages` を上げる —
  大規模テナントでは学期中の平日に `change_user_access` イベントが
  1日あたり数千件発生することがある。
- Google の `visibility=shared_externally` はファイルの**所有者**のドメインを
  基準にしているため、`internal_domains` が複数ある場合、内部ドメイン間の共有
  （例: 学生ドメイン → 教職員ドメイン）もこれに含まれる。そのため外部判定は
  `internal_domains` に対して付与先を照合して行う： 名前指定の付与なら
  `target_user`、ドメイン指定の付与なら `target_domain`（例: 「partner.edu の
  誰でも」。リテラルドメイン `"all"` は「リンクを知っている全員」を意味し、
  可視性側で判定する）。`risky_visibility_events` は `people_with_link` /
  `public_on_the_web` への遷移のみをカウントする（公開状態からリンク限定への
  縮小はカウントしない）。`untargeted_external_transitions` は、対象アドレスも
  ドメインも判定できない `shared_externally` への遷移の残余バケットで、
  他で見逃した付与のクロスチェックではない（ドメイン指定の付与は既に上で
  カウント済みのため）。`external_samples` / `exposure_samples` /
  `untargeted_samples` にはそれぞれの実例が入る。
- Drive イベントは**監査対象の eventName を1つずつ**問い合わせるため、
  閲覧/編集ノイズにページ予算を消費されない。API が拒否した eventName は
  ツール失敗ではなく `event_errors` に記録される。`change_document_visibility`
  と `change_document_access_scope` はこの API 上、同じ遷移を同時に姉妹
  イベントとして報告するが、分類には後者のみを使う（前者は `acl_events`
  件数のためだけに取得する）ため、ドメイン指定の付与やリンク/公開への露出が
  二重カウントされることはない。これは同時に、後者自体の取得が失敗した場合に
  前者では代替できないことも意味する： `change_document_access_scope` が
  `event_errors` に載ったドメインは `capped: true` になり、そのウィンドウの
  分類件数は下限値になる（`change_document_visibility` — ひいては
  `acl_events` — にはデータが出ていても）。
- 1ドメインでの失敗は、そのドメインのセクションのみを縮退させる
  （`{"error": ...}`）。
- 設計上 read-only — 発行する API 呼び出しは `activities().list` のみ。
- 出力にはアカウントアドレスが含まれる（監査ツールの目的上当然） —
  権限のあるセキュリティ担当者にアクセスを限定すること。

## 開発

```bash
git clone https://github.com/shigechika/gwsadm-mcp.git
cd gwsadm-mcp

# uv
uv sync --dev
uv run pytest -v
uv run ruff check .

# pip
python3 -m venv .venv
.venv/bin/pip install -e . && .venv/bin/pip install pytest ruff
.venv/bin/pytest -v
.venv/bin/ruff check .
```

## リリース

リリースは [release-please](https://github.com/googleapis/release-please) で
自動化されている。[Conventional Commits](https://www.conventionalcommits.org/)
（`feat:`、`fix:` 等）を `main` にマージすると、次バージョンと changelog を
持つリリース PR が維持される。その PR をマージすると `vX.Y.Z` がタグ付けされ
GitHub Release が公開され、`release: published` イベントが `release`
workflow を起動して PyPI と MCP Registry へビルド・公開する。バージョンは
`gwsadm_mcp/__init__.py` と `server.json` の両方を release-please が管理する
（手動で書き換えないこと）。

> [!IMPORTANT]
> release-please の workflow にはリポジトリシークレット `RELEASE_PLEASE_TOKEN`
> （`contents: write` + `pull-requests: write` を持つ PAT）を設定すること。
> 既定の `GITHUB_TOKEN` は下流の `release` workflow を起動する Release を
> 作成できない（GitHub が `GITHUB_TOKEN` 起因の workflow 起動をブロックする
> ため）ので、PAT がないと何も公開されない。シークレット未設定時は
> `GITHUB_TOKEN` にフォールバックするので、fork 上でも PR CI は動作する。

## ライセンス

MIT
