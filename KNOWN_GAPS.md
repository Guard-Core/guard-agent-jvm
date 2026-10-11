# KNOWN_GAPS

The gap ledger for guard-agent-jvm (W7). Entries are open only while work is
in flight; each tracks to closure, not to permanent documentation.

## Closed in W7 (recorded for the audit trail)

- G-A1 (CLOSED): full module port. Every Go file of guard-agent-go v3.2.2
  maps to a Kotlin file: agent.go -> GuardAgent.kt, config.go -> AgentConfig.kt,
  transport.go -> Transport.kt, persistence.go -> Persistence.kt,
  rate_limiter.go -> RateLimiter.kt, circuit_breaker.go -> CircuitBreaker.kt,
  encryption.go -> Encryption.kt, signing.go -> Signing.kt, redact.go ->
  Redaction.kt, errors.go -> AgentErrors.kt, models.go -> Models.kt,
  dynamic_rules.go -> DynamicRules.kt, error_hook.go -> ErrorHook.kt,
  install_id.go -> InstallId.kt, utils.go -> AgentUtils.kt, version.go ->
  Version.kt. Test surface: all 16 *_test.go files port (mock_test.go ->
  MockIngest.kt + TestSupport.kt, the coverage tiers -> CoverageTest.kt /
  CoverageMoreTest.kt / PersistenceIntegrationTest.kt) with the vendored
  encryption vectors byte-identical.

## Open

- G-A2 (idiom mapping, documented; tracks to W8 docs pass): the User-Agent
  header value is `guard-agent-jvm/<version>` where guard-agent-go sends
  `guard-agent-go/<version>` (transport.go `userAgent`). The family-suffix
  idiom: every family agent self-identifies (`guard-agent/<py>`,
  `guard-agent-go/<go>`); the ingestion API treats the value as opaque.
- G-A3 (idiom mapping, documented): context.Context ports to `AgentContext`
  (a cancellation token with deadline). The blocking agent surface keeps the
  Go call shapes; cancellation is observed at the documented pre-send,
  retry-sleep, and block-wait checkpoints plus mid-flight via the default
  dispatcher's watch loop. A custom `HttpDoer` observes `ctx` however its
  implementation chooses.
- G-A4 (idiom mapping, documented): Go test hooks are seam-injected
  (`cryptoRandRead`, `jsonMarshal`, `newGzipWriter`, `breaker.now`, and the
  go-redis command hooks -> `Persistence.commandFaultInjector`); behavior
  under fault is pinned by the same test arms.
- G-A5 (environment, documented): the Go test `TestDefaultInstallIDPathWithoutHome`
  pins the `HOME=""` arm via `t.Setenv`; the JVM cannot mutate the parent
  environment, so the reachable arm pins the home-rooted default path and the
  empty-home branch is covered structurally (InstallId.kt reads HOME then
  falls back to `user.home`).
- G-A6 (environment, documented): the Go integration tier gates on
  `REDIS_HOST` being SET (skips otherwise); the JVM tier gates on Redis
  reachability (PING `REDIS_HOST`, default `127.0.0.1:6379`, skip on
  failure). Same coverage, friendlier local runs; CI sets `REDIS_HOST` and
  runs a redis container either way.
- G-A7 (port-completeness note, no action until a facade gap is proven):
  `TestRecoverPanicInExportedMethods`'s second arm builds a persistence with
  a nil go-redis client, which PANICS through loadKind and surfaces as
  ErrInternal. The JVM has no nil-ness panic: any persistence failure is an
  exception, which is exactly the Go error path (fail-open, counted). The
  port asserts the reachable arm (status over an uninitialized transport
  surfaces ErrInternal; a failing startup reload degrades to memory-only and
  counts the failure) in
  `CoverageTest.recoverPanicInExportedMethods` /
  `PersistenceIntegrationTest.reloadSurvivesRedisOutage`.
- G-A8 (W8-owned): Dokka pages, the release rehearsal (tag flow + publish
  existence check), and the every-feature matrix rows for the agent surface
  land with the family W8 wave. The 3.2.2 tag is cut there, not in W7.
