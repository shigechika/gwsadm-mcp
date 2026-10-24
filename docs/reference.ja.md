# リファレンス

## ツール一覧

| ツール | 説明 |
|------|------|
| `health_check` | サーバーバージョン・設定パス・ドメインごとの認証確認 — セッション開始時やタイムアウト後に呼ぶ |
| `login_audit` | Reports API `login` — **Google により自動無効化されたアカウント**（`account_disabled_*`: 漏洩パスワード・乗っ取り・スパム送信）、不審なログイン、失敗の多い順トップN |
| `suspended_accounts` | Directory API — **停止中**アカウントの現在スナップショット（`isSuspended=true`）。下流 IdP（KeyCloak 等）と突合し、停止済みなのに IdP 側で有効なままのアカウントを洗い出す |
| `get_user` | Directory API `users().get` — **アドレスを指定した1アカウント**の現在の状態: `suspended`（理由・停止日時付き）、`archived`、`last_login`、2段階認証の登録/強制、組織部門、作成日時、次回ログイン時のパスワード変更要求。「なぜこの人はログインできないのか」に1リクエスト・ページングなしで答える。アドレスが既に分かっているときは `suspended_accounts` ではなくこちらを使う: あちらは停止中のアカウントだけを列挙するので、指定アドレスが停止**されていない**ことは確認できない。`suspended_accounts` が既に使っているスコープ以外は不要 |
| `user_oauth_tokens` | Directory API `tokens().list` — **特定ユーザー1名**の第三者OAuthアプリ連携一覧。既存トークンはログイン不要で使えるため `login_audit` では検知できない侵害経路。ドメインはユーザー名のサフィックスから解決（エイリアス/セカンダリドメインのアドレス用に `domain` で明示指定も可） |
| `sign_out_user` | **状態を変える・オプトイン。** Directory API `users().signOut` — **1アカウント**を全てのウェブ・端末のセッションからサインアウトさせ、ログイン Cookie をリセットする（先に `users().get` でアカウントの存在を確かめる）。サーバーを `GWSADM_ENABLE_SIGN_OUT=1` で起動したときだけ登録される。呼ぶ前に承認の段を置くこと。OAuth 付与・アプリパスワードの取り消し、登録済みの第2要素の削除、パスワードの変更はしない（`not_covered` に列挙）。付与が 2 つ要る: 事前のアカウント確認に `admin.directory.user.readonly`（`get_user` と同じ）、サインアウト自体に `admin.directory.user.security`（`user_oauth_tokens` と同じ）。なりすます管理者にユーザーのセキュリティ管理の権限も必要。`signed_out` は `true`（Google が成功を返した）・`false`（何も変わっていない）・`null`（送ったが時間内に答えが無く結果不明）の三値で、毎回同じキーを返す。全体を `GWSADM_SIGN_OUT_DEADLINE_SECONDS`（既定 45 秒）以内に終える。アドレス自身のドメインが設定済みであること、`domain` を渡すならそれと一致することが必要。 |
| `user_activity` | Reports API `activities().list` を `userKey=<username>` で — **特定アカウント1名**がウィンドウ内に Workspace 全体で行ったことを、アプリ横断（既定: login・token・user_accounts・drive・groups・calendar・chat・meet・saml）で新しい順にまとめる。`flags` は量に関係なくアカウントのセキュリティ姿勢を変えるイベント（2SV の登録/解除、復旧用メール/電話の変更、パスワード変更、ドメイン外への転送、Google 自身の `risky_sensitive_action_*` / `suspicious_login` 判定、OAuth の `authorize` 全件とそのクライアント・スコープ）を先頭に出す — 攻撃者が登録した第2要素はパスワードリセット後も残るため。`ips` は送信元アドレスごとの初見/最終を列挙。Google 自身の `account_disabled_*` / `suspicious_login` 判定は本人の `userKey` では返らない（actor が Google）ため、`login_audit` と同じ取り方で別に取得し、擬似アプリ `login_verdicts` として返す。`login_audit` では答えられない侵害後の問い（あれは Google 自身が挙げたイベントのドメイン全体ビュー） |
| `ip_activity` | Reports API `activities().list` を `actorIpAddress=<ip>` で — **特定の送信元アドレス1つ**が操作した全アカウントを、ドメイン別・アプリ別に、同じ `flags` 付きで。`user_activity` で攻撃者のアドレスが分かった後の追跡: 同じ送信元が他のアカウントにも届いたか。スプレーは成功前から `login_failure` の件数として現れる |
| `compromise_sweep` | **特定アカウント1名**の侵害が確定した後の Google 側の追跡を 1 回で: `activity`（`user_activity`、flags を先頭に）、`state` / `grants`（`get_user`、メール・Drive・連絡先・管理のスコープを持つ OAuth 付与を `risky` として明示）、`ips`（攻撃者のアドレス — 指定するか、本人の flags から取る — で全ドメインに `ip_activity`。本人は除外）、`gmail`: 攻撃者がメールを読み続けるために残す設定（自動転送・転送先アドレス・転送/削除/アーカイブするフィルタ・委任・送信者名とreply-to）と、ウィンドウ内に送った通数・宛先ドメイン — 件名・本文は読まない。`gmail.kind` が読めたかどうかを示す: `ok` / `partial`（設定の一部か送信サマリーが失敗。読めた分はそのまま）/ `api_disabled`（サービスアカウント自身の Cloud プロジェクトで Gmail API が無効）/ `no_grant` / `error` — 失敗は失敗として返し、「何も無かった」とは読まない。`highlights` に対応すべき事実、`checklist` に手作業で残ること。`gmail_message_trace` と同じ `gmail.readonly` DWD スコープ（設定の読み取りは `delegates.list` を含め全てこのスコープで通ることを実機で確認） |
| `drive_external_sharing` | Reports API `drive` — 外部アドレス/ドメインへの ACL **付与**（取り消しは別集計）、リンク公開/一般公開への可視性**遷移** |
| `drive_doc_activity` | Reports API `drive` をサーバー側 `doc_id` フィルタで — **特定1文書**の所有者・ACL 変更・ライフサイクル履歴。`drive_external_sharing` の検知トリアージ用: 所有者（個人か共有ドライブ名か）で誤検知クラスを切り分ける |
| `shared_drive_membership_changes` | Reports API `drive`（`shared_drive_membership_change`）— 共有ドライブのメンバー追加/削除/ロール変更の履歴。対象メンバーの外部判定と、クライアント側ドライブ名フィルタ付き |
| `admin_actions` | Reports API `admin` — 管理者（人、または管理者として動く同期・API クライアント）が管理コンソールで何をしたか。**特定の利用者・グループ**に対して（対象のドメインでサーバー側 `USER_EMAIL` / `GROUP_EMAIL` フィルタ）か、テナント全体。「このアカウントを停止した・パスワードを変えた・グループから外したのは誰か」に答える。管理イベントの行為者は管理者で、操作された側ではないので `user_activity` では答えられない |
| `workspace_status` | Google Workspace ステータスダッシュボード（公開フィード、認証不要）— 未解決の障害と、期間内に終わった障害。製品（`Gmail`、`Drive` など）で絞れる。テナント側を調べる前に「Google 側か」に答える |
| `gmail_message_trace` | Gmail API — **既知の** Message-ID が**特定の**メールボックスに届いたか、届いたならどこに入っているか（受信トレイ/迷惑メール/ゴミ箱/アーカイブ）を確認する。宛先ごとに DWD でそのユーザーになりすまし、本人のメールボックスを検索する。別付与の `gmail.readonly` DWD スコープが必要。未付与のドメインは宛先ごとのエラーとして報告され、誤って「届いていない」扱いにはならない |
| `gmail_usage_report` | Reports API `customerUsageReports` — ドメイン別・日次のGmail送受信通数、昨日まで（APIの日付基準はUTC-8:00／PST）。別付与の `admin.reports.usage.readonly` DWD スコープが必要 — `admin.reports.audit.readonly` とは同じReports APIでも別のグラント |
| `dmarc_rua_summary` | Gmail API — DMARC 集約（RUA）レポートのドメイン別 PASS/FAIL 集計と reject 候補送信元IPの上位一覧。ドメインの設定値 `dmarc_rua_mailbox`（実ユーザー。既定 `postmaster@<domain>`）になりすまし、`dmarc_rua_recipient`（既定は mailbox と同じ）宛のメールを検索して圧縮された添付レポートを読む。`dmarc_rua_mailbox = none` のドメインは `skipped` として返る。`gmail_message_trace` と同じ `gmail.readonly` DWD スコープを使うが、メタデータだけでなく添付内容を読む |
| `group_delivery_policy` | Groups Settings API — Google グループ自体の投稿/配送ポリシー（`who_can_post`、`allow_external_members`、モデレーションレベル）。別付与の `apps.groups.settings` DWD スコープが必要 |
| `list_group_members` | Directory API — Google グループの基本情報とメンバー一覧を直接取得する。別付与の `admin.directory.group.readonly` と `admin.directory.group.member.readonly` DWD スコープが必要 |
| `daily_brief` | 設定済み全ドメインを横断した一括サマリ。アカウントの保護の変更（2 段階認証・パスキー・高度な保護機能・パスワード・再設定用のメールと電話・ドメイン外への転送）を含み、国外（`GWSADM_IP2ASN`・`GWSADM_HOME_COUNTRIES`）から来たもの、出どころが引けないもの、不審なログインの後のものに印を付ける |
| `daily_brief_start` / `daily_brief_result` | `daily_brief` をバックグラウンド実行: `start` が即座に `job_id` を返し、`result(job_id)` を `done` になるまでポーリングする。同期呼び出しがクライアントの ~60秒 tool-call タイムアウトに掛かる大規模テナント向け |

計画中: `dlp_events`（Reports `rules`、DLP 対応の Workspace エディションが
必要）、`token_events`、`admin_events`。

## 認証モデルのスコープ表

基本セット — 以下の3つを同じサービスアカウントのクライアント ID に
最初にまとめて付与する:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`、`user_activity`、`ip_activity`、`admin_actions`、`drive_external_sharing`、`drive_doc_activity`、`shared_drive_membership_changes`、`daily_brief*` | それらのツールがドメイン単位のエラーに縮退 |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`、`get_user`、`sign_out_user`（オプトイン。事前のアカウント確認） | それらのツールだけエラーに縮退（`suspended_accounts` はドメイン単位）。他は動作を続ける |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens`・`sign_out_user`（オプトイン） | それらのツールだけドメイン単位のエラーに縮退。他は動作を続ける |

さらに5つ、それぞれ別付与のスコープ — 互いにも基本セットにも束ねない:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.usage.readonly` | `gmail_usage_report` | そのツールだけドメイン単位のエラーに縮退。他は動作を続ける |
| `https://www.googleapis.com/auth/gmail.readonly` | `gmail_message_trace`、`dmarc_rua_summary`、`compromise_sweep`（`gmail` 節） | それらのツールだけ宛先/ドメイン単位のエラーに縮退。他は動作を続ける |
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

本パッケージが呼び出す Google API はこれだけである: `activities().list()` と `customerUsageReports().get()`（Reports API）、
`users().list()`・`users().get()`・`tokens().list()`・`groups().get()`・
`members().list()`（Directory API）、`groups().get()`（Groups Settings API）、
そして Gmail API の `messages().list()` / `messages().get(format="metadata")`
（`gmail_message_trace` と `compromise_sweep`。後者は To/Cc/Bcc/Date ヘッダーのみ）、
`messages().list()` / `messages().get(format="full")` / `messages().attachments().get()`
（`dmarc_rua_summary`。メタデータだけでなくレポートの添付を読む）、設定の読み取り
`users().settings().getAutoForwarding()` / `forwardingAddresses().list()` /
`filters().list()` / `delegates().list()` / `sendAs().list()`（`compromise_sweep`）、
`users().getProfile()`（`health_check` の Gmail の確認）。
ほかに `workspace_status` が Google の公開ステータスフィードを認証情報なしで GET する。状態を変える呼び出しは `users().signOut()`
（Directory API）だけで、`sign_out_user` からしか呼ばれない。このツールは
サーバーを `GWSADM_ENABLE_SIGN_OUT=1` で起動したときだけ登録され、未設定なら
書き込みツールは 1 本も存在しない。クライアントのどこにも insert・update・
patch・delete の呼び出しは存在しない。

## CLI

```bash
gwsadm-mcp --version   # バージョンを表示して終了
gwsadm-mcp --check     # 全ドメインの設定・認証・API 疎通を検証して終了
gwsadm-mcp             # MCP サーバを起動（STDIO、既定）
```

`--check` の終了コード: 成功時 `0`、設定または認証失敗時は非ゼロ。

各ツールが従う `capped`・`found`・エラー形状の規約はリポジトリ README の
「補足」節を参照。
