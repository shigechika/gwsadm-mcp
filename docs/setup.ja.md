# セットアップ

## インストール

```bash
uv pip install gwsadm-mcp
# または
pip install gwsadm-mcp
```

またはソースから:

```bash
git clone https://github.com/shigechika/gwsadm-mcp.git
cd gwsadm-mcp
uv sync          # または: pip install -e .
```

## 認証方式

監査権限を持つ管理者になりすます、**ドメイン単位の委任（DWD）**付き
サービスアカウント。完全に非対話式 — ブラウザ操作もトークンのリフレッシュ
ローテーションも不要なので、無人実行できる（cron・MCP ゲートウェイ・CI）。

サービスアカウントのクライアント ID には、以下の DWD スコープを**最初に
まとめて全部**付与すること。ツールを作るたびに1つずつ追加していくと、
そのツールが実際に動くまでスコープ不足に気づかない。1箇所・1回で済ませる
ことでこの罠を避ける:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`、`drive_external_sharing`、`drive_doc_activity`、`shared_drive_membership_changes`、`daily_brief*` | それらのツールがドメイン単位のエラーに縮退 |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`、`get_user` | その2つのツールだけエラーに縮退（`suspended_accounts` はドメイン単位）。他は動作を続ける |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens` | そのツールだけドメイン単位のエラーに縮退。他は動作を続ける |

`health_check` はスコープが一切無くても応答する。グラント漏れが疑われる
ときこそ呼ぶツールで、自身が失敗する代わりにドメインごとの認証失敗を
構造化された結果として報告する。

!!! tip "残り3つは別付与のスコープ"
    `gmail_message_trace` には `gmail.readonly` が要る — なりすませる
    どのユーザーについても**メッセージ本文**まで読める、上の3つより明らかに
    広い付与（ツールのコード自体は常に `format="metadata"` しか要求しない
    が、その制約はグラント自体には効かない）。`apps.groups.settings` は
    `group_delivery_policy` を、`admin.directory.group.readonly` /
    `admin.directory.group.member.readonly` は `list_group_members` の
    独立した2つの半分をそれぞれカバーする。詳細は
    [リファレンス](reference.ja.md) のスコープ表と README の「認証方式」
    節を参照。

`suspended_accounts`・`get_user`・`user_oauth_tokens` はいずれも顧客テナント
全体を対象とする Reports 系ツールと異なり、設定済みドメイン単位で動作する
（Directory の `domain=`/`userKey=`）。突合したいドメインはそれぞれ
`[domain.*]` セクションの設定が必要。

## 設定

`GWSADM_CONFIG` で INI ファイルを指定する（既定値は
`~/.config/gwsadm-mcp/config.ini`、パーミッションは `0600` にする）:

```ini
[gwsadm]
# 省略可。省略時は全 [domain.*] セクション名が対象になる
internal_domains = example.edu, mail.example.edu

[domain.example.edu]
service_account_file = /path/to/service-account.json
subject = audit-admin@example.edu
customer_id = C0xxxxxxx
dmarc_rua_mailbox = postmaster@example.edu   # 省略可。既定値: postmaster@<domain>
```

監査対象の Workspace ドメインごとに1つの `[domain.*]` セクションを置く。
`internal_domains` は共有先を内部/外部に分類するための許可リスト。
`dmarc_rua_mailbox`（省略可）は `dmarc_rua_summary` がDMARC集約レポートを
読むためになりすますメールボックス。

`GWSADM_CONFIG` そのものが設定サーフェス全体であり、環境変数だけで
サーバーを設定する方法は存在しない。各 `service_account_file` はさらに
独立したもう1つのファイルパス依存で、自分の GCP プロジェクト固有の
Google Cloud サービスアカウント JSON 鍵を指す。どちらのファイルも
テンプレート化・環境変数置換・プラグインマニフェストでの配布ができず、
サーバーを動かすマシン上に事前に存在している必要がある。INI ファイルが
無い場合、あるいはドメインセクションに `service_account_file` /
`subject` / `customer_id` のいずれかが欠けている場合は全ツール呼び出しが
失敗する — スコープ不足とは違い、設定欠落に対する縮退動作は無い。

## 何かに組み込む前に確認する

```bash
gwsadm-mcp --check
```

`--check` の終了コード: 成功時 `0`、設定または認証失敗時は非ゼロ。
一度これを走らせておけば、「ツールが何も返さない」が既に答えの出ている
問いになる。

## MCP クライアントへの登録

### Claude Code（プラグイン）

このリポジトリはプラグイン1個のマーケットプレイスも兼ねている:

```
/plugin marketplace add shigechika/gwsadm-mcp
/plugin install gwsadm-mcp@gwsadm-mcp
```

プラグインは `uvx gwsadm-mcp` を起動し、上の「設定」節と同じ
`GWSADM_CONFIG`（未設定なら `~/.config/gwsadm-mcp/config.ini`）を読む。
`/plugin install` はサーバープロセスの配線を行うだけで、設定 INI やその
参照先の Google Cloud サービスアカウント JSON 鍵までは作ってくれない。
どちらもプラグインを動かすマシン上にあらかじめ用意しておく必要がある。

プラグインは `uvx` を起動するため、Claude Code を実行するプロセスの `PATH` に
`uvx` が通っている必要がある。ログインシェルなら通常問題ないが、GUI から起動した
場合は通っていないことがある。プラグインが起動しない場合は
[uv](https://docs.astral.sh/uv/) をシステム全体にインストールすること。

### Claude Code（手動）

`.mcp.json`（設定ファイルが既定パスにある場合は `env` 不要。既定以外の
パスの場合のみ `"env": { "GWSADM_CONFIG": "..." }` を追加）:

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

`claude_desktop_config.json` も同じエントリを `mcpServers` の下に置く。
完全な例はリポジトリの README を参照。

### 直接実行

```bash
gwsadm-mcp
```

## 次に

[リファレンス](reference.ja.md) で全ツール・完全なスコープ表・CLI・
終了コードを扱う。
