# Changelog

## [0.15.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.14.1...v0.15.0) (2026-09-01)


### Features

* add dmarc_rua_summary tool ([#79](https://github.com/shigechika/gwsadm-mcp/issues/79)) ([0e37703](https://github.com/shigechika/gwsadm-mcp/commit/0e3770330ee27a05f1bce4a3d5643e3a2abe4cd9))
* add gmail_usage_report tool ([#81](https://github.com/shigechika/gwsadm-mcp/issues/81)) ([c54ec0d](https://github.com/shigechika/gwsadm-mcp/commit/c54ec0de803b475bcee079424195be0bb9cd26aa))

## [0.14.1](https://github.com/shigechika/gwsadm-mcp/compare/v0.14.0...v0.14.1) (2026-08-20)


### Bug Fixes

* **login_audit:** name the account Google itself acted on ([#73](https://github.com/shigechika/gwsadm-mcp/issues/73)) ([a887184](https://github.com/shigechika/gwsadm-mcp/commit/a8871844e8773957f8ab885b45a4e90333bfa087))

## [0.14.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.13.0...v0.14.0) (2026-08-15)


### Features

* package the server as a Claude Code plugin ([#71](https://github.com/shigechika/gwsadm-mcp/issues/71)) ([21b6eee](https://github.com/shigechika/gwsadm-mcp/commit/21b6eee5d4cf3e83d2873cbca3661b42972193a3))

## [0.13.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.12.2...v0.13.0) (2026-08-14)


### Features

* add get_user, a single-account lookup ([#69](https://github.com/shigechika/gwsadm-mcp/issues/69)) ([898887c](https://github.com/shigechika/gwsadm-mcp/commit/898887c26e03f7f8bff43238643f7498070cd749))

## [0.12.2](https://github.com/shigechika/gwsadm-mcp/compare/v0.12.1...v0.12.2) (2026-08-13)


### Bug Fixes

* bump cryptography to 50.0.0 (Dependabot high-severity alert) ([#65](https://github.com/shigechika/gwsadm-mcp/issues/65)) ([e80f38b](https://github.com/shigechika/gwsadm-mcp/commit/e80f38ba63a55df570117b3792f16129ad3b09d6))

## [0.12.1](https://github.com/shigechika/gwsadm-mcp/compare/v0.12.0...v0.12.1) (2026-08-11)


### Bug Fixes

* add explicit workflow permissions to ci.yml and release.yml ([#63](https://github.com/shigechika/gwsadm-mcp/issues/63)) ([3606136](https://github.com/shigechika/gwsadm-mcp/commit/36061360058c820fa8658e6fef5cd3d5ef9e1d53))

## [0.12.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.11.0...v0.12.0) (2026-08-08)


### Features

* add pr-gate.yml admission control caller ([#61](https://github.com/shigechika/gwsadm-mcp/issues/61)) ([02bb16b](https://github.com/shigechika/gwsadm-mcp/commit/02bb16b6d7b0b17dd71b7e6897ddd62aedd3a65e))

## [0.11.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.10.0...v0.11.0) (2026-08-07)


### Features

* add group_delivery_policy and list_group_members tools ([#58](https://github.com/shigechika/gwsadm-mcp/issues/58)) ([dd16965](https://github.com/shigechika/gwsadm-mcp/commit/dd169658a90bd4e320cc924b8e2848cd33e015fe))

## [0.10.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.9.4...v0.10.0) (2026-08-06)


### Features

* add gmail_message_trace tool ([#54](https://github.com/shigechika/gwsadm-mcp/issues/54)) ([5c1bef7](https://github.com/shigechika/gwsadm-mcp/commit/5c1bef7cf296e142778192d80c41486962c6d924))

## [0.9.4](https://github.com/shigechika/gwsadm-mcp/compare/v0.9.3...v0.9.4) (2026-08-06)


### Bug Fixes

* **deps:** ignore mcp major version updates in Dependabot ([#50](https://github.com/shigechika/gwsadm-mcp/issues/50)) ([e75ac63](https://github.com/shigechika/gwsadm-mcp/commit/e75ac63e0406649d1aea56923071aa74ba23f60d))

## [0.9.3](https://github.com/shigechika/gwsadm-mcp/compare/v0.9.2...v0.9.3) (2026-07-31)


### Bug Fixes

* **deps:** cap the MCP SDK below v2 ([#46](https://github.com/shigechika/gwsadm-mcp/issues/46)) ([4360483](https://github.com/shigechika/gwsadm-mcp/commit/4360483698816797c36854c9eb4a9376c4bee426))

## [0.9.2](https://github.com/shigechika/gwsadm-mcp/compare/v0.9.1...v0.9.2) (2026-07-27)


### Bug Fixes

* **ci:** read AI-review guidance from the base revision, drop the checkout ([#44](https://github.com/shigechika/gwsadm-mcp/issues/44)) ([31ef34d](https://github.com/shigechika/gwsadm-mcp/commit/31ef34de742939bb4ee9d97834b307f57920c285))
* sync the smoke-test engine ([#42](https://github.com/shigechika/gwsadm-mcp/issues/42)) ([6ab46aa](https://github.com/shigechika/gwsadm-mcp/commit/6ab46aa001dc892c7828bd202ae8be72a471038b))

## [0.9.1](https://github.com/shigechika/gwsadm-mcp/compare/v0.9.0...v0.9.1) (2026-07-26)


### Bug Fixes

* close two holes the per-domain guard did not cover ([#39](https://github.com/shigechika/gwsadm-mcp/issues/39)) ([5a15c5d](https://github.com/shigechika/gwsadm-mcp/commit/5a15c5dde98341e30027025a51a7627347d3fe65))

## [0.9.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.8.0...v0.9.0) (2026-07-26)


### Features

* live smoke test that exercises every registered tool ([#37](https://github.com/shigechika/gwsadm-mcp/issues/37)) ([31c33fa](https://github.com/shigechika/gwsadm-mcp/commit/31c33fa1431232f0c2a4159d7abce32059565a5f))

## [0.8.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.7.0...v0.8.0) (2026-07-24)


### Features

* add drive_doc_activity and shared_drive_membership_changes tools ([#31](https://github.com/shigechika/gwsadm-mcp/issues/31)) ([2d70573](https://github.com/shigechika/gwsadm-mcp/commit/2d705732cb4d3761a21b5e44bc3e97577d9a2f63))

## [0.7.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.6.0...v0.7.0) (2026-07-14)


### Features

* add user_oauth_tokens tool (Directory API tokens().list) ([#23](https://github.com/shigechika/gwsadm-mcp/issues/23)) ([6d6e1fd](https://github.com/shigechika/gwsadm-mcp/commit/6d6e1fdd98e73c83f1522ae63b08772c318676d5))

## [0.6.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.5.0...v0.6.0) (2026-07-13)


### Features

* add suspended_accounts tool (Directory API snapshot) ([#17](https://github.com/shigechika/gwsadm-mcp/issues/17)) ([ff395ad](https://github.com/shigechika/gwsadm-mcp/commit/ff395ad8a7f3ab44ea35aab0688575a0f9b3b820))

## [0.5.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.4.0...v0.5.0) (2026-07-10)


### Features

* daily_brief_start / daily_brief_result background job+poll ([#10](https://github.com/shigechika/gwsadm-mcp/issues/10)) ([#13](https://github.com/shigechika/gwsadm-mcp/issues/13)) ([8c34a8e](https://github.com/shigechika/gwsadm-mcp/commit/8c34a8e09473d258162f8f16676b8a3b1c4372c1))

## [0.4.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.3.0...v0.4.0) (2026-07-10)


### Features

* add env-gated timeout_probe diagnostic tool (for [#10](https://github.com/shigechika/gwsadm-mcp/issues/10)) ([#11](https://github.com/shigechika/gwsadm-mcp/issues/11)) ([54651fb](https://github.com/shigechika/gwsadm-mcp/commit/54651fb56fe86c37d0e94f4d49a4a65388e25e41))

## [0.3.0](https://github.com/shigechika/gwsadm-mcp/compare/v0.2.2...v0.3.0) (2026-07-10)


### Features

* **server:** parallelize Reports API fetches so daily_brief fits the gateway timeout ([#8](https://github.com/shigechika/gwsadm-mcp/issues/8)) ([36fd100](https://github.com/shigechika/gwsadm-mcp/commit/36fd100ef13f89f0768017f5999a299e952d6f32))

## [0.2.2](https://github.com/shigechika/gwsadm-mcp/compare/v0.2.1...v0.2.2) (2026-07-09)


### Bug Fixes

* surface ipAddress and actor.profileId fallback in login_audit entries ([#6](https://github.com/shigechika/gwsadm-mcp/issues/6)) ([a5e9b07](https://github.com/shigechika/gwsadm-mcp/commit/a5e9b0761f12eb90809bfaa9bde5f5ce7987acae))

## [0.2.1](https://github.com/shigechika/gwsadm-mcp/compare/v0.2.0...v0.2.1) (2026-07-08)


### Bug Fixes

* catch asyncio.CancelledError on ^C, not just KeyboardInterrupt ([c7a3be2](https://github.com/shigechika/gwsadm-mcp/commit/c7a3be28b588858da1092f50f47297d40dca9979))
* skip the SIGINT test on Windows (signal semantics differ) ([5b195a0](https://github.com/shigechika/gwsadm-mcp/commit/5b195a075da704904efd9a56c9f2f7b89339ea42))

## Changelog
