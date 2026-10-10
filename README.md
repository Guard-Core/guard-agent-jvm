<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>JVM telemetry agent for the [Guard ecosystem](https://github.com/Guard-Core/guard-core): at-least-once shipping of security events, metrics, and status to the Guard Core App ingestion API.</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
</p>

___

## Status

W0 scaffold. The repo builds with the Gradle toolchain (JDK 17, Kotlin) and CI is wired, but no agent functionality exists yet. The functional modules (buffering, transport, circuit breaker, Redis persistence, encryption, signing, redaction, dynamic rules) land in W7, mirroring [guard-agent-go](https://github.com/Guard-Core/guard-agent-go).

## What lands here

- Per-kind queues (events, metrics) with size and time flush triggers.
- At-least-once shipping with retry, backoff, and a circuit breaker.
- Optional Redis persistence, AES-GCM encryption at rest, HMAC signing.
- Redaction and dynamic rules controlling what ships.

## Install

Not published yet. The first artifact ships with the 3.2.2 release.

## License

[MIT](LICENSE)
