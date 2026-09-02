# リファレンス

## ツール一覧

| ツール | 説明 |
|------|------|
| `health_check` | サーバーバージョン・設定パス・ドメインごとの認証確認 — セッション開始時やタイムアウト後に呼ぶ |
| `login_audit` | Reports API `login` — **Google により自動無効化されたアカウント**（`account_disabled_*`: 漏洩パスワード・乗っ取り・スパム送信）、不審なログイン、失敗の多い順トップN |
| `suspended_accounts` | Directory API — **停止中**アカウントの現在スナップショット（`isSuspended=true`）。下流 IdP（KeyCloak 等）と突合し、停止済みなのに IdP 側で有効なままのアカウントを洗い出す |
| `get_user` | Directory API `users().get` — **アドレスを指定した1アカウント**の現在の状態: `suspended`（理由・停止日時付き）、`archived`、`last_login`、2段階認証の登録/強制、組織部門、作成日時、次回ログイン時のパスワード変更要求。「なぜこの人はログインできないのか」に1リクエスト・ページングなしで答える。アドレスが既に分かっているときは `suspended_accounts` ではなくこちらを使う: あちらは停止中のアカウントだけを列挙するので、指定アドレスが停止**されていない**ことは確認できない。`suspended_accounts` が既に使っているスコープ以外は不要 |
| `user_oauth_tokens` | Directory API `tokens().list` — **特定ユーザー1名**の第三者OAuthアプリ連携一覧。既存トークンはログイン不要で使えるため `login_audit` では検知できない侵害経路。ドメインはユーザー名のサフィックスから解決（エイリアス/セカンダリドメインのアドレス用に `domain` で明示指定も可） |
| `drive_external_sharing` | Reports API `drive` — 外部アドレス/ドメインへの ACL **付与**（取り消しは別集計）、リンク公開/一般公開への可視性**遷移** |
| `drive_doc_activity` | Reports API `drive` をサーバー側 `doc_id` フィルタで — **特定1文書**の所有者・ACL 変更・ライフサイクル履歴。`drive_external_sharing` の検知トリアージ用: 所有者（個人か共有ドライブ名か）で誤検知クラスを切り分ける |
| `shared_drive_membership_changes` | Reports API `drive`（`shared_drive_membership_change`）— 共有ドライブのメンバー追加/削除/ロール変更の履歴。対象メンバーの外部判定と、クライアント側ドライブ名フィルタ付き |
| `gmail_message_trace` | Gmail API — **既知の** Message-ID が**特定の**メールボックスに届いたか、届いたならどこに入っているか（受信トレイ/迷惑メール/ゴミ箱/アーカイブ）を確認する。宛先ごとに DWD でそのユーザーになりすまし、本人のメールボックスを検索する。別付与の `gmail.readonly` DWD スコープが必要。未付与のドメインは宛先ごとのエラーとして報告され、誤って「届いていない」扱いにはならない |
| `gmail_usage_report` | Reports API `customerUsageReports` — ドメイン別・日次のGmail送受信通数、昨日まで（APIの日付基準はUTC-8:00／PST）。別付与の `admin.reports.usage.readonly` DWD スコープが必要 — `admin.reports.audit.readonly` とは同じReports APIでも別のグラント |
| `dmarc_rua_summary` | Gmail API — DMARC 集約（RUA）レポートのドメイン別 PASS/FAIL 集計と reject 候補送信元IPの上位一覧。ドメインの設定値 `dmarc_rua_mailbox`（実ユーザー。既定 `postmaster@<domain>`）になりすまし、`dmarc_rua_recipient`（既定は mailbox と同じ）宛のメールを検索して圧縮された添付レポートを読む。`dmarc_rua_mailbox = none` のドメインは `skipped` として返る。`gmail_message_trace` と同じ `gmail.readonly` DWD スコープを使うが、メタデータだけでなく添付内容を読む |
| `group_delivery_policy` | Groups Settings API — Google グループ自体の投稿/配送ポリシー（`who_can_post`、`allow_external_members`、モデレーションレベル）。別付与の `apps.groups.settings` DWD スコープが必要 |
| `list_group_members` | Directory API — Google グループの基本情報とメンバー一覧を直接取得する。別付与の `admin.directory.group.readonly` と `admin.directory.group.member.readonly` DWD スコープが必要 |
| `daily_brief` | 設定済み全ドメインを横断した一括サマリ |
| `daily_brief_start` / `daily_brief_result` | `daily_brief` をバックグラウンド実行: `start` が即座に `job_id` を返し、`result(job_id)` を `done` になるまでポーリングする。同期呼び出しがクライアントの ~60秒 tool-call タイムアウトに掛かる大規模テナント向け |

計画中: `dlp_events`（Reports `rules`、DLP 対応の Workspace エディションが
必要）、`token_events`、`admin_events`。

## 認証モデルのスコープ表

基本セット — 以下の3つを同じサービスアカウントのクライアント ID に
最初にまとめて付与する:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`、`drive_external_sharing`、`drive_doc_activity`、`shared_drive_membership_changes`、`daily_brief*` | それらのツールがドメイン単位のエラーに縮退 |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`、`get_user` | その2つのツールだけエラーに縮退（`suspended_accounts` はドメイン単位）。他は動作を続ける |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens` | そのツールだけドメイン単位のエラーに縮退。他は動作を続ける |

さらに5つ、それぞれ別付与のスコープ — 互いにも基本セットにも束ねない:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.usage.readonly` | `gmail_usage_report` | そのツールだけドメイン単位のエラーに縮退。他は動作を続ける |
| `https://www.googleapis.com/auth/gmail.readonly` | `gmail_message_trace`、`dmarc_rua_summary` | それらのツールだけ宛先/ドメイン単位のエラーに縮退。他は動作を続ける |
| `https://www.googleapis.com/auth/apps.groups.settings` | `group_delivery_policy` | そのツールだけエラーに縮退。他は動作を続ける |
| `https://www.googleapis.com/auth/admin.directory.group.readonly` | `list_group_members`（グループ情報側） | この側だけが自分のエラーを返す。下のメンバー用スコープが付与されていればメンバー一覧側は独立して動作する |
| `https://www.googleapis.com/auth/admin.directory.group.member.readonly` | `list_group_members`（メンバー一覧側） | 同上、上のグループ情報側とは独立 — 2つの呼び出しは互いをブロックしない |

`gmail.readonly` は基本セットより明らかに広い付与である: なりすませる
どのユーザーについても、メタデータだけでなく**メッセージ本文**まで
読める権限になる。ツールのコード自体は常に `format="metadata"` しか
要求しないが、その制約はグラント自体には効かない。実際にどこまで
メッセージトレースが必要かと、この広い露出とを天秤にかけたうえで判断
すること。より狭い `gmail.metadata` スコープがなぜ不採用だったかを含む
完全な経緯は README の「認証方式」節を参照。

## 読み取り専用の範囲

本パッケージが呼び出す Google API はこれだけである: `activities().list()`
（Reports API）、`users().list()`・`users().get()`・`tokens().list()`・
`groups().get()`・`members().list()`（Directory API）、`groups().get()`
（Groups Settings API）、`messages().list()`・`messages().get()`（Gmail
API、メタデータのみ）。クライアントのどこにも insert・update・patch・
delete の呼び出しは存在しない — `write_tools` が空なのは慣習ではなく
構造による。

## CLI

```bash
gwsadm-mcp --version   # バージョンを表示して終了
gwsadm-mcp --check     # 全ドメインの設定・認証・API 疎通を検証して終了
gwsadm-mcp             # MCP サーバを起動（STDIO、既定）
```

`--check` の終了コード: 成功時 `0`、設定または認証失敗時は非ゼロ。

各ツールが従う `capped`・`found`・エラー形状の規約はリポジトリ README の
「補足」節を参照。
