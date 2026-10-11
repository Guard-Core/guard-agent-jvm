# Contributing to Guard Agent JVM

Thanks for considering a contribution to guard-agent-jvm, the JVM telemetry
agent of the Guard ecosystem. The agent is a true port of
[guard-agent-go](https://github.com/Guard-Core/guard-agent-go) v3.2.2:
behavior 1:1 with byte-exact observable surfaces (wire payloads, header
names, event/metric model shapes, config keys, AES-GCM and HMAC parameters
pinned against the Go test vectors).

## Development Setup

Requirements:

- JDK 17 (the build pins the JVM toolchain to 17)
- Docker (the Redis durability test tier runs against a live server, via `docker run -p 6379:6379 redis:7-alpine`)

## Engine dependency

The agent is engine-free at runtime (compile-only facade contract) but builds
against the guard-core-jvm composite for the protocol surfaces: CI checks out
Guard-Core/guard-core-jvm at the pinned ref as the sibling directory
`./guard-core-jvm`. Locally:

```bash
git clone https://github.com/Guard-Core/guard-core-jvm ../guard-core-jvm
git -C ../guard-core-jvm checkout 5f4ea56
./gradlew build          # detekt + ktfmt check + the full test suite
```

Set `GUARD_CORE_USE_COMPOSITE=false` to build without the composite (the
release-workflow mode).

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
./gradlew detekt ktfmtCheck --no-daemon   # static analysis + formatting
./gradlew build --no-daemon              # full suite incl. the Redis durability tier
```

The version catalog (`gradle/libs.versions.toml`) is the single source of
truth for every third-party pin; the committed `gradle.lockfile` is enforced
on every resolution (a dependency change without `./gradlew --write-locks`
fails the build) and scanned in CI with osv-scanner. Dependency additions
need justification in the PR adding them.

## Port fidelity

Behavior changes must stay byte-exact with the Go reference: the crypto test
vectors (vendored from the Go repo) and the wire shapes are the gate. When
the Go agent changes, port first, then adjust the JVM surface.

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
