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
| `gmail_usage_report` | Reports API `customerUsageReports` — ドメイン別・日次のGmail送受信通数。1日1回のAPI呼び出しで、対象は昨日まで（APIの日付基準はUTC-8:00／PST）。別付与の `admin.reports.usage.readonly` DWD スコープが必要（下記「認証方式」参照）— `admin.reports.audit.readonly` とは同じReports APIでも別のグラント |
| `suspended_accounts` | Directory API — **停止中**アカウントの現在スナップショット（`isSuspended=true`）。下流 IdP（KeyCloak 等）と突合し、停止済みなのに IdP 側で有効なままのアカウントを洗い出す |
| `get_user` | Directory API `users().get` — **アドレスを指定した1アカウント**の現在の状態： `suspended`（理由・停止日時付き）、`archived`、`last_login`、2段階認証の登録/強制、組織部門、作成日時、次回ログイン時のパスワード変更要求。「なぜこの人はログインできないのか」に1リクエスト・ページングなしで答える。アドレスが既に分かっているときは `suspended_accounts` ではなくこちらを使う： あちらは停止中のアカウントだけを列挙するので、指定アドレスが停止**されていない**ことは確認できない（さらにその一覧がページ上限を超えると、載っていないこと自体が根拠にならなくなる）。`suspended_accounts` が既に使っているスコープ以外は不要 |
| `user_oauth_tokens` | Directory API `tokens().list` — **特定ユーザー1名**の第三者OAuthアプリ連携一覧。既存トークンはログイン不要で使えるため `login_audit` では検知できない侵害経路。ドメインはユーザー名のサフィックスから解決（エイリアス/セカンダリドメインのアドレス用に `domain` で明示指定も可） |
| `drive_external_sharing` | Reports API `drive` — 外部アドレス/ドメインへの ACL **付与**（取り消しは別集計）、リンク公開/一般公開への可視性**遷移** |
| `drive_doc_activity` | Reports API `drive` をサーバー側 `doc_id` フィルタで — **特定1文書**の所有者・ACL 変更・ライフサイクル履歴。`drive_external_sharing` の検知トリアージ用： 所有者（個人か共有ドライブ名か）で「共有ドライブ内のファイル作成が既存メンバーへの ACL 伝播として一括外部共有に見える」誤検知クラスを切り分ける |
| `shared_drive_membership_changes` | Reports API `drive`（`shared_drive_membership_change`）— 共有ドライブのメンバー追加/削除/ロール変更の履歴。対象メンバーの外部判定と、クライアント側ドライブ名フィルタ付き |
| `gmail_message_trace` | Gmail API — **既知の** Message-ID が**特定の**メールボックスに届いたか、届いたならどこに入っているか（受信トレイ/迷惑メール/ゴミ箱/アーカイブ）を確認する。宛先ごとに DWD でそのユーザーになりすまし、本人のメールボックスを検索する。別付与の `gmail.readonly` DWD スコープが必要（下記「認証方式」参照）。未付与のドメインは宛先ごとのエラーとして報告され、誤って「届いていない」扱いにはならない |
| `dmarc_rua_summary` | Gmail API — DMARC 集約（RUA）レポートのドメイン別 PASS/FAIL 集計と、reject 候補となる送信元IPの上位一覧。ドメインの設定値 `dmarc_rua_mailbox`（実ユーザー。既定 `postmaster@<domain>`）になりすまし、`dmarc_rua_recipient`（公開している `rua=` 宛先、例 `postmaster+rua@`。既定は mailbox と同じ）宛のメールを検索してレポートの添付を読む。`gmail_message_trace` と同じ `gmail.readonly` DWD スコープを使うが、こちらは（メタデータだけでなく）添付内容＝レポートXMLを実際に読む点が異なる — 下記「認証方式」参照 |
| `group_delivery_policy` | Groups Settings API — Google グループ自体の投稿/配送ポリシー（`who_can_post`、`allow_external_members`、モデレーションレベル）。グループのアクセス制御は Gmail 配送の**手前**にある： 学内限定の投稿ポリシーは外部送信者のメールを、Gmail の配送イベントが1件も生成されないまま静かに落とす — ポリシーを直接読まない限り配送失敗と見分けがつかない。別付与の `apps.groups.settings` DWD スコープが必要（下記「認証方式」参照） |
| `list_group_members` | Directory API — Google グループの基本情報とメンバー一覧を直接取得する。特定のメッセージがたまたま誰に届いたかから推測するのではない。別付与の `admin.directory.group.readonly` と `admin.directory.group.member.readonly` DWD スコープが必要（下記「認証方式」参照） |
| `daily_brief` | 設定済み全ドメインを横断した一括サマリ |
| `daily_brief_start` / `daily_brief_result` | `daily_brief` をバックグラウンド実行： `start` が即座に `job_id` を返し、`result(job_id)` を `done` になるまでポーリングする。同期呼び出しがクライアントの ~60秒 tool-call タイムアウトに掛かる大規模テナント向け |

計画中： `dlp_events`（Reports `rules`、DLP 対応の Workspace エディションが必要）、
`token_events`、`admin_events`。

## 認証方式

監査権限を持つ管理者になりすます、**ドメイン単位の委任（DWD）**付きサービスアカウント。
完全に非対話式 — ブラウザ操作もトークンのリフレッシュローテーションも不要なので、
無人実行できる（cron・MCP ゲートウェイ・CI）。

サービスアカウントのクライアント ID には、以下の DWD スコープを**最初にまとめて全部**付与すること。
ツールを作るたびに1つずつ追加していくと、そのツールが実際に動くまでスコープ不足に気づかない
（今回がまさにそれだった）。1箇所・1回で済ませることでこの罠を避ける:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `login_audit`、`drive_external_sharing`、`drive_doc_activity`、`shared_drive_membership_changes`、`daily_brief*` | それらのツールがドメイン単位のエラーに縮退 |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `suspended_accounts`、`get_user` | その2つのツールだけエラーに縮退（`suspended_accounts` はドメイン単位）。他は動作を続ける |
| `https://www.googleapis.com/auth/admin.directory.user.security` | `user_oauth_tokens` | そのツールだけドメイン単位のエラーに縮退。他は動作を続ける |

`health_check` はスコープが一切無くても応答する。グラント漏れが疑われるときこそ呼ぶツールで、
自身が失敗する代わりにドメインごとの認証失敗を構造化された結果として報告する。

`gmail_usage_report` にも専用のスコープが要る。上のまとめ付与と同じAdmin SDK Reports API
配下だが、「使用量レポート」系（`customerUsageReports`）と「監査」アクティビティストリーム
（`activities().list`、上のまとめ付与の他ツールが使うもの）は別スコープで、片方を
持っていてももう片方は付与されない:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/admin.reports.usage.readonly` | `gmail_usage_report` | そのツールだけドメイン単位のエラーに縮退。他は動作を続ける |

`gmail_message_trace` と `dmarc_rua_summary` にはもう1つスコープが要るが、これは
意図的に上のまとめ付与とは**別立て**にしてある:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/gmail.readonly` | `gmail_message_trace`、`dmarc_rua_summary` | それらのツールだけ宛先/ドメイン単位のエラーに縮退。他は動作を続ける |

これは上の3つより明らかに広い付与である： サービスアカウントがなりすませる
どのユーザーについても、メタデータだけでなく**メッセージ本文**まで読める権限になる。
`gmail_message_trace` は常に `format="metadata"` しか要求せず本文は一切読まないが、
`dmarc_rua_summary` は実際に本文相当の内容を読む — RUA メールが持つ圧縮レポート添付を
`format="full"` と `attachments().get()` で取得し、パースする。どちらもこのグラント範囲を
超えることはないが、「メタデータのみ」という狭い作法を保っているのは `gmail_message_trace`
だけである。より狭い `gmail.metadata` スコープも両ツールについて検討したが、
`rfc822msgid:`／RUAメールボックス検索に必要な `q=` パラメータをこのスコープは
サポートしないため採用しなかった。他のスコープと**同じ**サービスアカウントの
クライアント ID に付与すること（管理コンソール → セキュリティ → API の制御 →
ドメイン全体の委任 → 既存のクライアント ID を探す → このスコープをリストに追加）。
実際にどこまでメッセージトレース／DMARCレポート機能が必要かと、この広い露出とを
天秤にかけたうえで、ドメインごとに付与するかどうかを判断すること。

`group_delivery_policy` と `list_group_members` にもそれぞれ専用スコープが要る。
上のまとめ付与とも `gmail.readonly` とも束ねない、さらに3つの別立てグラント:

| スコープ | 必要とするツール | 未付与の場合 |
|------|------|------|
| `https://www.googleapis.com/auth/apps.groups.settings` | `group_delivery_policy` | そのツールだけエラーに縮退。他は動作を続ける |
| `https://www.googleapis.com/auth/admin.directory.group.readonly` | `list_group_members`（グループ情報側） | この側だけが自分のエラーを返す。下のメンバー用スコープが付与されていればメンバー一覧側は独立して動作する |
| `https://www.googleapis.com/auth/admin.directory.group.member.readonly` | `list_group_members`（メンバー一覧側） | 同上、上のグループ情報側とは独立——2つの呼び出しは互いをブロックしない |

Groups Settings API は Directory API とは別プロダクトなのでスコープも別立てになっている。
読み取り専用バリアントは存在しないが、本サーバーが呼ぶのは `groups().get()` のみで、
変更系メソッドは一切呼ばない。

`suspended_accounts`・`get_user`・`user_oauth_tokens` はいずれも Reports 系ツール（顧客テナント全体）と異なり、
設定済みドメイン単位で動作する（Directory の `domain=`/`userKey=`）。突合したいドメイン
（例：学生用の別ドメイン）はそれぞれ `[domain.*]` セクションの設定が必要。
なお失敗の仕方が異なる点に注意：未設定ドメインを `suspended_accounts` は**黙って結果から省く**が、
`get_user` と `user_oauth_tokens` は unknown-domain エラーで明示的に失敗する
（どちらもサフィックスに対応するセクションが無いエイリアス/セカンダリドメインのアドレス用に
`domain` の明示指定を受け付ける）。

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
dmarc_rua_mailbox = postmaster@example.edu   # 省略可。既定値: postmaster@<domain>。"none" で対象外
dmarc_rua_recipient = postmaster+rua@example.edu   # 省略可。既定値: dmarc_rua_mailbox と同じ
```

監査対象の Workspace ドメインごとに1つの `[domain.*]` セクションを置く。
`internal_domains` は共有先を内部/外部に分類するための許可リスト。
`dmarc_rua_mailbox` は `dmarc_rua_summary` がDMARC集約レポートを読むためになりすます
**実ユーザー**（ドメイン全体の委任はグループやエイリアスにはなりすませない）。
`dmarc_rua_recipient` はレポートの宛先（ドメインの `_dmarc` レコードに公開している
`rua=mailto:` の値）で、Gmail 検索の絞り込み（`to:<recipient>`）にだけ使う。既定値は
mailbox と同じ。公開している宛先が `postmaster+rua@` のような Gmail のプラスサブアドレス
（この絞り込みにより `postmaster+ruf@` 宛の `ruf=` 失敗レポートも集計から外れる）や、
なりすまし先の受信箱へ配送されるグループのときに設定する。`dmarc_rua_mailbox = none` で
そのドメインを DMARC 読み取りの対象外にできる — 例えば `rua=` が別ドメインのメールボックス
宛で、そちらの `[domain.*]` セクションが既に読んでいる場合。レポートは各レポートが名乗る
ポリシードメインごとに集計されるので、そのセクションの結果に含まれる。

## 使い方

### Claude Code（プラグイン）

このリポジトリはプラグイン1個のマーケットプレイスも兼ねているので、Claude Code から
そのまま導入できる:

```
/plugin marketplace add shigechika/gwsadm-mcp
/plugin install gwsadm-mcp@gwsadm-mcp
```

プラグインは `uvx gwsadm-mcp` を起動し、上の「設定」節と同じ `GWSADM_CONFIG`
（未設定なら `~/.config/gwsadm-mcp/config.ini`）を読む。`/plugin install` は
サーバープロセスの配線を行うだけで、設定 INI やその参照先の Google Cloud
サービスアカウント JSON 鍵までは作ってくれない。どちらもプラグインを動かす
マシン上にあらかじめ用意しておく必要がある。

プラグインは `uvx` を起動するため、Claude Code を実行するプロセスの `PATH` に
`uvx` が通っている必要がある。ログインシェルなら通常問題ないが、GUI から起動した
場合は通っていないことがある。プラグインが起動しない場合は
[uv](https://docs.astral.sh/uv/) をシステム全体にインストールすること。

### Claude Code（手動）

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
- `gmail_message_trace` は、同じ Message-ID を持つメッセージが宛先メールボックス内に
  複数存在する場合（メーリングリスト経由＋直接CC、隔離解放時の重複など）、
  `ambiguous: true`（`match_count` 付き）を返す — その他のフィールドは最初の1件
  だけを表しており、複数件を統合した答えではない点に注意。検索はページングしないため、
  一定件数以上マッチした場合は `match_count` が正確な件数ではなく下限値であることを示す
  `match_count_capped` も併せて立つ。
- `get_user` は「このアドレスに該当するアカウントが無い」ことと「取得に失敗した」ことを
  区別する： 単純な HTTP 404 は状態フィールドを付けずに `found: false` を返す。これは
  タイプミスや削除済みアドレスという**診断結果**であって `error` ではない。DWDスコープ未付与や
  一時的な失敗は `found` キーを付けずに `{"error": ...}` を返すので、どちらの方向にも
  取り違えは起きない。Google の応答に無いフィールドは `null` のままで丸めない —
  `suspended` が欠落しているのを「このアカウントは問題なし」と読んではいけない。
- `group_delivery_policy` は Groups Settings API の `"true"`/`"false"` 文字列
  フィールド（JSON boolean ではなく、この API 固有の癖）を実際の boolean に
  正規化して返す。Google の応答に無いフィールドは `null` のままで、`false`
  に丸めない。`list_group_members` はグループ情報取得とメンバー一覧取得を
  互いに独立して実行する — DWDスコープが片方しか付与されていないテナントでも、
  付与されている方のセクションは返り、もう片方はそこに `{"error": ...}` を
  埋め込む形で報告する。`capped: true` は、メンバー一覧がページ予算（既定20
  ページ × 200件/ページ）を超えた場合と、メンバー取得自体が失敗した場合
  （`members_error` 参照）の両方で返す — どちらも全件ではないという点は同じで、
  `capped` が true のとき `members` が空でも「メンバー0名と確認できた」と
  誤読してはいけない。
  両ツールとも「このアドレスはグループではない」（3つの API 呼び出しすべてで
  本番確認済みの、単純な HTTP 404）を本当のエラーと区別する:
  `group_delivery_policy` は `found: false` を返す。`list_group_members` も
  同様に返すが、それは2つの独立した取得が**両方とも**エラーなしで一致して
  「見つからない」と答えたとき、または片方が「見つからない」と確定し、
  もう片方は独立して失敗しただけのとき（その失敗は `group_lookup_error` /
  `members_lookup_error` として隠さず添える）——確定した非存在は、もう片方の
  無関係なエラーより強い根拠として扱う。片方が見つからず、もう片方は本当に
  データを見つけた、という真の混在状態だけが通常のセクション別の形に
  フォールバックする。
- 設計上 read-only — このパッケージが発行する API 呼び出しは `activities().list`
  （Reports API）、`users().list` / `users().get` / `tokens().list` /
  `groups().get` / `members().list`（Directory API）、`groups().get`（Groups Settings API）、
  `messages().list` / `messages().get`（Gmail API、メタデータのみ）に限られる。
- 出力にはアカウントアドレスが含まれる（監査ツールの目的上当然） —
  権限のあるセキュリティ担当者にアクセスを限定すること。`gmail_message_trace`
  はマッチしたメッセージのスニペットとヘッダー（From/To/Cc/Subject/Date）も返す —
  取り扱いはメールボックスの中身そのものと同等の注意で扱うこと。

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

### ライブスモークテスト

ユニットテストは Google に一切接続しない。それが速さの理由であり、同時に
「ツールが実データを返さなくなったこと」を検出できない理由でもある。
`scripts/smoke_test.py` は設定済みのテナントに対して**登録されている全ツール**を
実行し、空・不正・エラー応答を失敗として報告する。

```bash
# サーバーと同じ設定ファイル（GWSADM_CONFIG）を使う
uv run python scripts/smoke_test.py
uv run python scripts/smoke_test.py --only oauth --traceback
```

- **読み取り専用**。ここにあるツールは監査ログかディレクトリのスナップショットを
  読むだけで、Workspace 側は変更しない。`daily_brief_start` はプロセス内にジョブを
  作るが、これは自動で期限切れになる。
- **レポートにペイロードを出さない**。ツール名・ステータス・件数のみ。これらのツールは
  終始アカウントアドレスや文書タイトルを扱うため、サーバー由来のエラー文言も伏字にする。
- **上限を明示**。ツールが持つ上限パラメータは全て明示的に渡す。既定値
  （5ページ・180日・200イベント）は対話利用向けであり、ソースから見つけて強制するテスト付き。
- **テナント固有の値を spec に書かない**。ユーザー単位・文書単位のツールが必要とする
  アカウントと文書 ID は実行時に発見し、テナントに materials が無ければスキップする。
  2本のテストで担保: 該当パラメータの直値を拒否し、アドレス的な形がファイル内に
  現れることを禁じる（公開リポジトリのため）。
- 応答が空でも合格。外部共有ゼロ・ロックされたアカウントゼロは望ましい状態だからだ。
  代わりに表明するのは体裁（envelope）と、ドメイン別の応答についてはドメインマップが
  空でないこと。ドメイン0件の設定は、何も監査していないのに全ツール正常と報告してしまう。
- CI では安価な半分を強制する。probe spec の無いツールを登録するとビルドが失敗するので
  （`tests/test_smoke_probes.py`）、ツール追加時に「どうやって動作を確認するか」を必ず決めることになる。
- `scripts/smoke_harness.py` はエンジンであり Workspace 固有の知識を持たない。このハーネスを
  共有する各サーバーで同一に保つ方針なので、エンジンのバグはこの写しを直すのではなく
  一度直して全体に同期する。

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