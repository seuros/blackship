# Changelog

## [0.3.1](https://github.com/seuros/blackship/compare/blackship-v0.3.0...blackship-v0.3.1) (2026-11-09)


### Bug Fixes

* **armada:** merge config files at the TOML level ([7f6b948](https://github.com/seuros/blackship/commit/7f6b94896aff3fd4a45dd1550cac0218830a8e1f))
* **build:** resolve destinations the way the jail sees them ([0b4d762](https://github.com/seuros/blackship/commit/0b4d762d454a644383427a40d1e33648396ae55c))
* **cli:** escalate for build, armada build, logs and gc ([69dfd07](https://github.com/seuros/blackship/commit/69dfd075366ff2166b6ea119af21c7dbdb03cf6b))
* **lifecycle:** skip jails already in the target state ([94486c3](https://github.com/seuros/blackship/commit/94486c3a07c2252c722ccb2c5f0bb86b52c83f47))
* **manifest:** derive the project name from the canonical config dir ([5914486](https://github.com/seuros/blackship/commit/5914486913aabc82541b1aa52b1fd42ea72d56f9))
* **pf:** evaluate the blackship anchor and its drain sub-anchors ([0960a96](https://github.com/seuros/blackship/commit/0960a96948b1faf9701fe1579d1805752724ea7f))
* **pf:** match bind-address forwards on the destination ([a723e1f](https://github.com/seuros/blackship/commit/a723e1fcdca43099a92823ccc02da88f3aba8380))
* **pf:** treat a loaded but disabled PF as off ([d5f4740](https://github.com/seuros/blackship/commit/d5f4740e4672914b47a561c3a00c8e1a524cf6d9))
* **releases:** delete through the ZFS-aware library call ([9b494fb](https://github.com/seuros/blackship/commit/9b494fbe0ae240b3431d98747ebdddd77d936d7c))

## [0.3.0](https://github.com/seuros/blackship/compare/blackship-v0.2.1...blackship-v0.3.0) (2026-11-09)


### Features

* **cli:** add capabilities discovery ([#24](https://github.com/seuros/blackship/issues/24)) ([977fee9](https://github.com/seuros/blackship/commit/977fee9546a1d5d82ef8440563bd93135a5c5e03))
* **cli:** add privilege escalation controls ([#19](https://github.com/seuros/blackship/issues/19)) ([829f8c4](https://github.com/seuros/blackship/commit/829f8c4e5dce72abf8c92dd034d38556e37baf2f))
* **cli:** add structured lifecycle plans ([#23](https://github.com/seuros/blackship/issues/23)) ([4b106a4](https://github.com/seuros/blackship/commit/4b106a4aef73b4d8a07c79910759350ea5867d6d))
* **cli:** extend structured read-only output ([#22](https://github.com/seuros/blackship/issues/22)) ([017d9dc](https://github.com/seuros/blackship/commit/017d9dcb53205a7ca1746aa8f3e3de2571d810dd))
* **container:** allow_chflags for baking images with pkgbase ([3bb9d40](https://github.com/seuros/blackship/commit/3bb9d405825345a3eb79aebc6e6fc11983d24ed4))
* **container:** hand a container over to another owner ([cd12ef2](https://github.com/seuros/blackship/commit/cd12ef20128e44a7b8ead854122e8bb966b8eecd))
* **container:** nosuid and noexec for nullfs mounts ([8a1050a](https://github.com/seuros/blackship/commit/8a1050a76ed145621b5a13921192ab5514a7f819))


### Bug Fixes

* **build:** support FreeBSD 15.1 jail headers ([#21](https://github.com/seuros/blackship/issues/21)) ([2417759](https://github.com/seuros/blackship/commit/241775956b7aee66ffbc7fd6d3281e484efd7d87))
* **container:** give VNET containers a resolver ([80724f5](https://github.com/seuros/blackship/commit/80724f52ded46cd264fabf8496b4c70c13ccd7e7))
* **container:** reap a timed-out command before sweeping its jail ([025ff3a](https://github.com/seuros/blackship/commit/025ff3acce62d6d4ac60b944a605962ed9ced7ca))
* **rctl:** NUL-terminate rule strings and expand size suffixes ([c506956](https://github.com/seuros/blackship/commit/c506956f7143052b5d2d4faf845e30b442291986))


### Miscellaneous Chores

* release 0.3.0 ([d2b6ab7](https://github.com/seuros/blackship/commit/d2b6ab71ec0d17ed0700398d1f23f92920e88e01))

## [0.2.1](https://github.com/seuros/blackship/compare/blackship-v0.2.0...blackship-v0.2.1) (2026-11-09)


### Features

* **cli:** add machine-readable output contract ([#18](https://github.com/seuros/blackship/issues/18)) ([b037e53](https://github.com/seuros/blackship/commit/b037e53b469b679af8818906450849767d574068))
* **lib:** public library API for ephemeral containers, releases and images ([b703f6c](https://github.com/seuros/blackship/commit/b703f6cba12ecbcf3d844eb006c7b65415b38ae7))
* **network:** add shared jail network option ([935f9e0](https://github.com/seuros/blackship/commit/935f9e0ff93507b2d5beb5a7b0bdf07ac6b4f5dc))
* **privilege:** support mdo escalation ([#17](https://github.com/seuros/blackship/issues/17)) ([0ecfe9c](https://github.com/seuros/blackship/commit/0ecfe9cf48a5bec21262e17f605897024b7289e2))


### Bug Fixes

* **cli:** mdo escalation resets the caller's environment; lint [#18](https://github.com/seuros/blackship/issues/18) ([5b82e02](https://github.com/seuros/blackship/commit/5b82e0284c72a88005b9337a93557b2a9c4ba1f6))

## [0.2.0](https://github.com/seuros/blackship/compare/blackship-v0.1.9...blackship-v0.2.0) (2026-10-11)


### ⚠ BREAKING CHANGES

* **scope:** scope records written by 0.1.9 and earlier no longer load.

### Features

* **mcp:** stdio server for authoring and validating jail configuration ([1cf3745](https://github.com/seuros/blackship/commit/1cf3745686f1391a56b1f0e6b1a307566e4aae58))
* retire the dead code by wiring up the features it belonged to ([8bd0d90](https://github.com/seuros/blackship/commit/8bd0d901d0fe6a0c1edd9675d95e11ded6295a73))
* **scope:** drive supervision and scope records with state-machines ([4f14403](https://github.com/seuros/blackship/commit/4f14403a171b17b90f51acba285de053855db59c))
* **scope:** durable jail lifecycle, orphan GC, QoS phases, drain, OTLP ([dab8fdc](https://github.com/seuros/blackship/commit/dab8fdc51ae157382c4357ae22cf155bfcf09e64))


### Bug Fixes

* **build:** honour --dry-run when the base release is absent ([dc4a801](https://github.com/seuros/blackship/commit/dc4a801cc949124a5d5d7eb8bfe88efff3b499bf))
* **build:** show LABEL key and value in template inspect ([c3fe4f8](https://github.com/seuros/blackship/commit/c3fe4f8860d2f75acb1921cdd14e6cc4f0012c80))


### Performance Improvements

* stop allocating on paths that discard the allocation ([7003a5d](https://github.com/seuros/blackship/commit/7003a5d9ae5a8daa824c6a83a50c8566975cfd5f))

## [0.1.9](https://github.com/seuros/blackship/compare/blackship-v0.1.8...blackship-v0.1.9) (2026-09-11)


### Features

* **eva:** hot-update running jails via jail_set(JAIL_UPDATE) ([824194c](https://github.com/seuros/blackship/commit/824194c1ab0f9e19c64c98fad2326089ca072930))
* **jail:** reserved params from sys/jail.h JAIL_PARAM constants ([dc23dc9](https://github.com/seuros/blackship/commit/dc23dc9629ffb25c1132bfbe42f4885459dae148))

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
