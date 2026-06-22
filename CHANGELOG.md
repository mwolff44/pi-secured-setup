# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-06-22

### Changed
- Bumped peer dependencies `@earendil-works/pi-ai`, `@earendil-works/pi-coding-agent`, and `@earendil-works/pi-tui` from `^0.79.6` to `^0.79.9`
- Synchronized `package-lock.json` with the peer dependency bump

### Security
- Resolved 10 Dependabot advisories that remained in `@earendil-works/pi-coding-agent@0.79.6` bundled copies, now fixed by the upstream `0.79.9` release
- `undici` (7): GHSA-vxpw-j846-p89q, GHSA-38rv-x7px-6hhq, GHSA-vmh5-mc38-953g, GHSA-p88m-4jfj-68fv, GHSA-pr7r-676h-xcf6, GHSA-g8m3-5g58-fq7m, GHSA-35p6-xmwp-9g52
- `protobufjs` (2): GHSA-wcpc-wj8m-hjx6, GHSA-f38q-mgvj-vph7
- `ws` (1): GHSA-96hv-2xvq-fx4p

## [1.0.2] - 2026-06-18

### Fixed
- Patched non-bundled transitive dependencies reachable via `@earendil-works/pi-ai` → `@google/genai` using npm `overrides`
- Bumped `protobufjs` to `7.6.4` and `ws` to `8.21.0` in the non-bundled dependency tree

### Security
- Mitigated Dependabot advisories for `protobufjs` (GHSA-wcpc-wj8m-hjx6, GHSA-f38q-mgvj-vph7, GHSA-jggg-4jg4-v7c6) and `ws` (GHSA-96hv-2xvq-fx4p, GHSA-58qx-3vcg-4xpx) where reachable
- Bundled copies inside `@earendil-works/pi-coding-agent@0.79.6` (`undici`, `protobufjs`, `ws`) remain and require an upstream bump from the `@earendil-works` publisher

## [1.0.1] - 2026-06-18

### Fixed
- Resolved critical and high-severity security vulnerabilities
- Fixed bugs in `splitCommand` and `triggerSkillReview`
- Made subshell splitting quote-aware and improved audit redaction
- Isolated audit tests from the real `HOME` directory and prevented skill name collisions
- Addressed all remaining Copilot PR review findings

### Changed
- Migrated package namespace from `@mariozechner` to `@earendil-works`
- Updated dependencies and documented future improvements

## [1.0.0] - 2026-05-07

### Added
- Initial release
- Guards: boundary enforcement, protected paths, and bash gate
- Scanners: secret detection and skill approval
- Append-only rotating JSONL audit trail
- Layered configuration (defaults, machine, project)
- Test suite
