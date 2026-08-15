# gwsadm-mcp

Google Workspace の**セキュリティ監査**用 MCP（Model Context Protocol）サーバ。
アカウントロック・不審なログイン・外部へのファイル共有への読み取り専用の
可視性を提供する。Admin SDK Reports API（監査アクティビティ）をベースに構築。

管理コンソールの視点にちなんで `gwsadm`（= Google Workspace admin）と命名。
[`boxadm-mcp`](https://github.com/shigechika/boxadm-mcp) の姉妹サーバ。
汎用的な Workspace MCP では**ない**： リスクを可視化するだけで、何も変更しない。

## 領域別ツール

| 領域 | ツール |
|---|---|
| 朝の点検 | `health_check`、`daily_brief`、`daily_brief_start`、`daily_brief_result` |
| ログイン・アカウント | `login_audit`、`suspended_accounts`、`get_user` |
| OAuth | `user_oauth_tokens` |
| Drive | `drive_external_sharing`、`drive_doc_activity`、`shared_drive_membership_changes` |
| Gmail | `gmail_message_trace` |
| グループ | `group_delivery_policy`、`list_group_members` |

計画中: `dlp_events`（Reports `rules`、DLP 対応の Workspace エディションが
必要）、`token_events`、`admin_events`。

## 設計方針

**ドメイン単位の委任（DWD）付きサービスアカウント認証であること自体が
設計の要です。** 本サーバーは人間のサインインではなく、監査権限を持つ
管理者になりすますサービスアカウントで認証します。完全に非対話式 —
ブラウザ操作もトークンのリフレッシュローテーションも不要なので、
cron・MCP ゲートウェイ・CI から無人実行できます。

**取得を打ち切ったときは、打ち切ったことを明示します。** 各結果セクションは、
ウィンドウがページ予算を超えた場合やプローブの取得自体がエラーになった場合に
`capped: true` を返します。部分的な結果を「該当なし」として提示することは
ありません。Drive 系ツールはさらに一歩進んで、どのイベント種別が打ち切られた
かを正確に記録します。

**慣習ではなく構造として読み取り専用です。** 本パッケージが呼び出す Google API
は `activities().list()`（Reports API）、`users().list()` / `users().get()` /
`tokens().list()` / `groups().get()` / `members().list()`（Directory API）、
`groups().get()`（Groups Settings API）、`messages().list()` /
`messages().get()`（Gmail API、メタデータのみ）だけです。クライアントのどこにも
insert・update・patch・delete の呼び出しは存在せず、どんなスコープを付与しても
このサーバーが書き込みツールに変わることはありません。

## 次に読むもの

- [セットアップ](setup.ja.md) — インストール・DWD スコープ・`[domain.*]`
  設定ファイル・MCP クライアントへの登録
- [リファレンス](reference.ja.md) — 全ツール・認証モデルのスコープ表・CLI・
  終了コード
