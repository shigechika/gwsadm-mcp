# Changelog

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
