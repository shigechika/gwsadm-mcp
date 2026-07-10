# Changelog

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
