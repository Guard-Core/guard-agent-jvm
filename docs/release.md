# Release runbook (guard-agent-jvm)

Agent release choreography. The shared mechanics (Portal namespace, user
token, GPG, publishing limits, rollback semantics) are documented once in the
engine repo: [guard-core-jvm docs/release.md](https://github.com/Guard-Core/guard-core-jvm/blob/master/docs/release.md).
This file covers what differs here.

## Versioning law

- Artifact `com.guard-core:guard-agent-jvm`; version `3.2.4`, mirroring
  guard-agent 3.2.4 (the family versioning law, lockstep with the engines at
  guard-core 4.3.3). The version lives in
  `build.gradle.kts`; the tag must equal it.
- The engine lockstep pin lives in `gradle/libs.versions.toml` (`guardCore =
  "4.3.3"`); it moves only when the engine train moves. The published POM
  carries NO guard-core dependency (compile-only): the agent artifact stays
  engine-free at runtime, exactly like the Go agent library.
- Tags are bare `vX.Y.z` only (`v3.2.4`). The `verify` job of release.yml audits
  this (the guard-core-rs invisible-rule incident on `refs/tags/v4.3.2` is
  the standing lesson).
- groupId `com.guard-core`; Kotlin packages stay `com.guardcore.*`.

## Version-flip checklist (the release PR)

The workflow enforces this: releasing a tag without the flip fails the
`verify` job with an explicit message.

- [ ] `build.gradle.kts`: `version = "3.2.4-SNAPSHOT"` -> `version = "3.2.4"`.
- [ ] `gradle/libs.versions.toml`: `guardCore` still reads the lockstep engine
      version (`4.3.3`).
- [ ] The pinned engine ref (ci.yml clone step + settings comments) already
      points at the released engine SHA (bumped at train time, per the
      family spec).
- [ ] `CHANGELOG.md`: `## Unreleased (3.2.4-SNAPSHOT)` renamed to
      `## [3.2.4] - YYYY-MM-DD` with the engine pin stated.
- [ ] CI green on the release PR; merge it; tag the merge commit.

## Release choreography

Hard order: the engine artifacts MUST be live on Maven Central first. The
`pre-flight` job checks both `com.guard-core:guard-core-engine` and
`com.guard-core:guard-core` at the pinned lockstep version on repo1.maven.org
and refuses to run anything if they are not. This is load-bearing for the
agent too, not ceremony: in composite-OFF (release) mode the compile-only
facade coordinates resolve from the repositories (mavenLocal, then Maven
Central).

1. Complete the engine train first: guard-core-jvm tagged, released, Portal
   deployments released, repo1 answering 200 for both engine artifacts
   (engine docs/release.md, steps 1 and 5).
2. Merge the version-flip PR.
3. Tag: `git tag v3.2.4 && git push origin v3.2.4`. The tag push runs
   nothing: the merge commit's push run of ci.yml (build and tests against the
   pinned engine, dependency audit) is the gate.
4. Create the GitHub release for `v3.2.4`. release.yml runs no build or
   test for validation. The `verify` job checks the tag is bare `vX.Y.z`,
   equals the in-file version (and is not a SNAPSHOT), and that the newest
   push run of ci.yml on the tagged commit succeeded (it waits up to an hour
   for runs still in progress). The pre-flight job then requires both engine
   artifacts live on Maven Central. Then the publish job:
   - verifies the four secrets are set (Portal user token + GPG key);
   - checks repo1 for this exact artifact and skips if already live
     (changed-only rerun safety);
   - builds the staging bundle with `GUARD_CORE_USE_COMPOSITE=false`;
   - uploads the bundle to the Central Portal Publisher API
     (`publishingType=USER_MANAGED`) and polls until VALIDATED.
5. Release the deployment in the Portal UI (central.sonatype.com, Publishing
   -> Deployments).
6. Verify liveness:
   `curl -f https://repo1.maven.org/maven2/com/guard-core/guard-agent-jvm/3.2.4/guard-agent-jvm-3.2.4.pom`

## Post-release audits (per train)

1. Release page for `v3.2.4` exists with the expected notes (per-tag audit;
   the php v4.3.1 lesson).
2. repo1 answers 200 for the artifact (the same check the workflow uses).
3. No deployment left VALIDATED/PENDING in the Portal.
4. The pinned engine ref (ci.yml clone step + settings comments) moves to
   the released engine SHA AT TRAIN TIME, before the consumer tags: the
   agent's push CI must run against the engine that actually ships
   (the family spec pins this; a pin bump is an ordinary development PR).

## Rerun safety, failure recovery, rollback

Same rules as the engine runbook: a workflow_dispatch re-drive (Actions >
Release > Run workflow, `tag` input) checks that tag out with master's current
workflow and skips anything already live on repo1; a VALIDATED deployment you do not want gets Dropped in
the Portal; published artifacts are immutable - no rollback after the Portal
Release click, only a fix version.
