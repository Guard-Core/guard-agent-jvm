# Installation

## Requirements

- JDK 17 or newer
- Redis 6+ (optional: only for the persistence tier - write-on-enqueue with a
  TTL, delete-on-confirm, reload on start, fail-open on any Redis error)

## Coordinates

Published on Maven Central as `com.guard-core:guard-agent-jvm:3.2.3`. The group ID is `com.guard-core` (the Central Portal namespace); Kotlin packages stay `com.guardcore.*`.

```kotlin
dependencies {
    implementation("com.guard-core:guard-agent-jvm:3.2.3")
}
```

To build from source instead:

```bash
git clone https://github.com/Guard-Core/guard-core-jvm.git ../guard-core-jvm   # engine, pinned ref 2415a77
git clone https://github.com/Guard-Core/guard-agent-jvm.git
cd guard-agent-jvm && ./gradlew build
```

Set `GUARD_CORE_USE_COMPOSITE=false` to build without the composite: the
declared engine coordinates then resolve from the repositories (mavenLocal
first, then Maven Central) - this is how the release workflow proves the
published artifact graph.

The agent is engine-free at runtime: the published POM carries no guard-core
dependency (the facade protocol surfaces are compile-only). Wiring the agent
into the engine happens at the consumer side through the facade sink bridge
(see [API](api.md)).

## Dependency locking

`gradle.lockfile` is committed and enforced on every resolution: a dependency
change without `./gradlew --write-locks` fails the build. CI additionally
scans the lockfile with osv-scanner (fail on any known vulnerability).
