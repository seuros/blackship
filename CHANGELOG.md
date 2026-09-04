# Changelog

## [0.1.8](https://github.com/seuros/blackship/compare/blackship-v0.1.7...blackship-v0.1.8) (2026-09-04)


### Features

* add Docker-style run, cp, and rm commands ([#5](https://github.com/seuros/blackship/issues/5)) ([df3208f](https://github.com/seuros/blackship/commit/df3208f4ea3fc8136bc5223d943f5e8e623dd78a))
* add FreeBSD ports, init command, and armada orchestration ([2e57ac2](https://github.com/seuros/blackship/commit/2e57ac220b8d0613fcadcc7016c91afa73abde27))
* add FreeBSD ports, init command, and armada orchestration ([2971c99](https://github.com/seuros/blackship/commit/2971c99834ff2e0903692a78d4e4309d24c8a7f9))
* initial release - FreeBSD jail manager with state machine control ([5e3760d](https://github.com/seuros/blackship/commit/5e3760dc1af3e37a75643ec5cd952d6776468c66))
* netgraph VNET backend, ZFS clone provisioning, foreign imports, and hardening ([674c6ce](https://github.com/seuros/blackship/commit/674c6cefd6e61569bead37eea8b85e55f5f3bde0))
* restrict compilation to FreeBSD only ([890593e](https://github.com/seuros/blackship/commit/890593ea1789290c84b2f913dd3509bdf0750271))
* use XDG-compliant user directories as default paths ([#7](https://github.com/seuros/blackship/issues/7)) ([e09d4f2](https://github.com/seuros/blackship/commit/e09d4f27268b70a09cf99d8cc5cec1ce2dfa3a73))


### Bug Fixes

* **armada:** honor --build/--no-build on armada up ([f9db541](https://github.com/seuros/blackship/commit/f9db5416cc5630d85da74a847dc6a6572853c14e))
* persist networks and auto-escalate privileged commands ([dc27aca](https://github.com/seuros/blackship/commit/dc27aca50bf8bddf8ced3d38c845b567461ddaac))
* **proc:** share host-command runner, stop masking exec failures ([59ed065](https://github.com/seuros/blackship/commit/59ed065ce6ab1f2b5c3eec241731c035c0cd5920))
* stabilize vnet runtime state and cleanup ([5faa1f5](https://github.com/seuros/blackship/commit/5faa1f5135dc34106dc5aab1c547e769c45f23f9))
* **supply:** fail fast on non-retryable statuses, dedupe probe retry loop ([d57c8ab](https://github.com/seuros/blackship/commit/d57c8ab5b4456ce5bdc92c3c630cca2f5bfbe1ef))
* use jiff for wall-clock timestamps ([443168d](https://github.com/seuros/blackship/commit/443168de511530ce42984737304e1a3d5d0af13a))

## [0.1.7](https://github.com/seuros/blackship/compare/blackship-v0.1.6...blackship-v0.1.7) (2026-09-04)


### Bug Fixes

* **armada:** honor --build/--no-build on armada up ([bf6fed3](https://github.com/seuros/blackship/commit/bf6fed36c90765c07086ff88b5d7bed361e551a6))
* **proc:** share host-command runner, stop masking exec failures ([e39df0c](https://github.com/seuros/blackship/commit/e39df0cf88a23332ac739c452cee16decf7375a5))
* **supply:** fail fast on non-retryable statuses, dedupe probe retry loop ([69818cd](https://github.com/seuros/blackship/commit/69818cd90f2794825082660d937e4cf8166e520c))

## [0.1.6](https://github.com/seuros/blackship/compare/blackship-v0.1.5...blackship-v0.1.6) (2026-08-09)


### Features

* netgraph VNET backend, ZFS clone provisioning, foreign imports, and hardening ([0163357](https://github.com/seuros/blackship/commit/01633572a5f0f369acd2e984ab1e554902012011))

## [0.1.5](https://github.com/seuros/blackship/compare/blackship-v0.1.4...blackship-v0.1.5) (2026-05-01)


### Bug Fixes

* persist networks and auto-escalate privileged commands ([e562cc2](https://github.com/seuros/blackship/commit/e562cc20e65d77d6cd1515884dcfc1809073cec5))
* stabilize vnet runtime state and cleanup ([0bb8dca](https://github.com/seuros/blackship/commit/0bb8dca635b3fcb0934f178f99845fd5fb48bf9d))
* use jiff for wall-clock timestamps ([8033207](https://github.com/seuros/blackship/commit/8033207c446ac3217bb85fb5b59ca09427cf830e))

## [0.1.4](https://github.com/seuros/blackship/compare/blackship-v0.1.3...blackship-v0.1.4) (2026-01-25)


### Features

* add Docker-style run, cp, and rm commands ([#5](https://github.com/seuros/blackship/issues/5)) ([96fb395](https://github.com/seuros/blackship/commit/96fb395fc6a25e38612ae81c6897b71a97cff951))
* use XDG-compliant user directories as default paths ([#7](https://github.com/seuros/blackship/issues/7)) ([cd3f5a3](https://github.com/seuros/blackship/commit/cd3f5a3c569bc07b51a08d5ceea13ce2e3232d91))

## [0.1.3](https://github.com/seuros/blackship/compare/blackship-v0.1.2...blackship-v0.1.3) (2026-01-02)


### Features

* add FreeBSD ports, init command, and armada orchestration ([11b8833](https://github.com/seuros/blackship/commit/11b88333fb49a7bf2a34bdf4e78d9ac2076de09b))
* add FreeBSD ports, init command, and armada orchestration ([9f60244](https://github.com/seuros/blackship/commit/9f60244a5a6bd79b953ebb14a22c8f2f9b26512c))
* initial release - FreeBSD jail manager with state machine control ([5e3760d](https://github.com/seuros/blackship/commit/5e3760dc1af3e37a75643ec5cd952d6776468c66))
* restrict compilation to FreeBSD only ([d482182](https://github.com/seuros/blackship/commit/d48218209c20072b3fcd57de3d38cfd34d5a49cb))

## [0.1.2](https://github.com/seuros/blackship/compare/blackship-v0.1.1...blackship-v0.1.2) (2026-01-02)


### Features

* add FreeBSD ports, init command, and armada orchestration ([11b8833](https://github.com/seuros/blackship/commit/11b88333fb49a7bf2a34bdf4e78d9ac2076de09b))
* add FreeBSD ports, init command, and armada orchestration ([9f60244](https://github.com/seuros/blackship/commit/9f60244a5a6bd79b953ebb14a22c8f2f9b26512c))
* restrict compilation to FreeBSD only ([d482182](https://github.com/seuros/blackship/commit/d48218209c20072b3fcd57de3d38cfd34d5a49cb))

## [0.1.1](https://github.com/seuros/blackship/compare/blackship-v0.1.0...blackship-v0.1.1) (2025-12-28)


### Features

* initial release - FreeBSD jail manager with state machine control ([5e3760d](https://github.com/seuros/blackship/commit/5e3760dc1af3e37a75643ec5cd952d6776468c66))
