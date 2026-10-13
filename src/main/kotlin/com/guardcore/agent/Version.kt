package com.guardcore.agent

/**
 * Port of guard-agent-go `version.go`: the agent module version, reported to the ingestion API as
 * `agent_version` and in the User-Agent header. The 3.2.3 line mirrors guard-agent 3.2.3 (the
 * family versioning law, lockstep with the engines at 4.3.3); releases ship as v-prefixed git tags.
 */
public const val AGENT_VERSION: String = "3.2.3"

/**
 * The User-Agent header value (transport.go `userAgent`): the module name over the version. The
 * family-suffix idiom maps the Go module name to the JVM artifact name, exactly as every other
 * family agent self-identifies.
 */
public fun userAgent(): String = "guard-agent-jvm/" + AGENT_VERSION
