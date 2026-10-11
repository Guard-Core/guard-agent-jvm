package com.guardcore.agent

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Port of guard-agent-go `install_id_test.go` + install_id coverage arms. */
class InstallIdTest {
  private val uuid4Pattern =
      Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

  private fun quiet(): java.util.logging.Logger = quietLogger()

  @Test
  fun resolveInstallIDOverrideWins() {
    val got = resolveInstallID("override-id", tempDirFor("iid-override").toString(), quiet())
    assertEquals("override-id", got)
  }

  @Test
  fun resolveInstallIDPersistsAndReuses() {
    val logger = CapturingLogger()
    val path = tempDirFor("iid-persist").resolve("install-id")
    val first = resolveInstallID("", path.toString(), logger)
    assertTrue(uuid4Pattern.matches(first), "first id $first is not a uuid")
    assertEquals(first, Files.readString(path).trim(), "file contents must match")
    val second = resolveInstallID("", path.toString(), logger)
    assertEquals(first, second, "second id must reuse the persisted one")
    assertEquals("", logger.output(), "unexpected warnings: ${logger.output()}")
  }

  @Test
  fun resolveInstallIDEmptyFileRegenerates() {
    val path = tempDirFor("iid-empty").resolve("install-id")
    Files.writeString(path, "\n")
    val got = resolveInstallID("", path.toString(), quiet())
    assertTrue(uuid4Pattern.matches(got), "expected fresh uuid, got $got")
  }

  @Test
  fun resolveInstallIDFailOpen() {
    val logger = CapturingLogger()
    // A file occupying the parent-directory slot makes createDirectories fail.
    val blocker = tempDirFor("iid-block").resolve("blocker")
    Files.writeString(blocker, "x")
    val got =
        resolveInstallID("", blocker.resolve("nested").resolve("install-id").toString(), logger)
    assertTrue(uuid4Pattern.matches(got), "fail-open must still return a uuid, got $got")
    assertTrue(
        logger.output().contains("could not create install id directory"),
        "expected a warning log, got \"${logger.output()}\"",
    )
  }

  // coverage_test.go TestResolveInstallIDPaths: the remaining arms.

  @Test
  fun resolveInstallIDPaths() {
    val logger = quiet()
    assertEquals("explicit", resolveInstallID("explicit", "", logger))
    val dir = tempDirFor("iid-paths")
    val statePath = dir.resolve("sub").resolve("install-id")
    val first = resolveInstallID("", statePath.toString(), logger)
    val second = resolveInstallID("", statePath.toString(), logger)
    assertTrue(first.isNotEmpty() && first == second, "install id must persist across resolves")
    // A whitespace-only file falls through to a fresh id.
    val emptyPath = dir.resolve("empty-id")
    Files.writeString(emptyPath, "  \n")
    assertTrue(resolveInstallID("", emptyPath.toString(), logger).isNotEmpty())
    // A directory at the state path: read fails (logged, not ErrNotExist),
    // the write also fails, and the id still resolves in memory.
    assertTrue(resolveInstallID("", dir.toString(), logger).isNotEmpty())
    // A path under a regular file: createDirectories fails and is logged.
    val blocker = dir.resolve("blocker")
    Files.writeString(blocker, "x")
    assertTrue(
        resolveInstallID("", blocker.resolve("sub").resolve("id").toString(), logger).isNotEmpty(),
    )
    // A file with a genuine read error (permission denied) must log, not crash.
    val denied = dir.resolve("denied")
    Files.writeString(denied, "secret")
    try {
      Files.setPosixFilePermissions(denied, PosixFilePermissions.fromString("---------"))
      resolveInstallID("", denied.toString(), logger)
    } finally {
      Files.setPosixFilePermissions(denied, PosixFilePermissions.fromString("rw-r--r--"))
    }
  }

  @Test
  fun defaultInstallIDPathUnderHome() {
    // The Go test pins the HOME="" arm via t.Setenv; the JVM cannot
    // mutate the parent environment (an idiom mapping recorded in
    // KNOWN_GAPS.md), so the reachable arm pins the home-rooted path.
    val home = System.getenv("HOME") ?: System.getProperty("user.home")
    if (home.isNullOrEmpty()) {
      assertEquals("", defaultInstallIDPath(), "no home must yield an empty default path")
    } else {
      assertTrue(defaultInstallIDPath().contains(".guard-agent"), defaultInstallIDPath())
    }
  }
}
