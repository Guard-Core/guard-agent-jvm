package com.guardcore.agent

import java.nio.file.Files
import java.nio.file.Path
import java.util.logging.Logger

/**
 * Port of guard-agent-go `install_id.go`: install identity. The agent reports a stable install ID
 * in the X-Agent-Install-Id header. Resolution order mirrors guard-agent (Python) install_id.py: an
 * explicit config override wins; otherwise the ID is read from (or created in) a state file,
 * defaulting to ~/.guard-agent/install-id. Every filesystem failure is fail-open: the agent logs
 * and falls back to a fresh in-memory UUID rather than surfacing an error to the host application.
 */
internal fun resolveInstallID(
    override: String,
    path: String,
    logger: Logger,
): String {
  if (override.isNotEmpty()) {
    return override
  }
  var statePath = path
  if (statePath.isEmpty()) {
    statePath = defaultInstallIDPath()
  }
  if (statePath.isEmpty()) {
    return newUUID4()
  }
  val file = Path.of(statePath)
  try {
    if (Files.exists(file)) {
      val id = Files.readString(file).trim()
      if (id.isNotEmpty()) {
        return id
      }
    }
  } catch (e: Exception) {
    // Every read failure other than not-exist is logged (Go: !errors.Is(err,
    // os.ErrNotExist)), including the is-a-directory case.
    logger.warning("guardagent: could not read install id file $statePath: $e")
  }
  val id = newUUID4()
  val parent = file.toAbsolutePath().parent
  try {
    Files.createDirectories(parent)
  } catch (e: Exception) {
    logger.warning("guardagent: could not create install id directory $parent: $e")
    return id
  }
  return try {
    Files.writeString(file, id + "\n")
    id
  } catch (e: Exception) {
    logger.warning("guardagent: could not persist install id to $statePath: $e")
    id
  }
}

internal fun defaultInstallIDPath(): String {
  val home = System.getenv("HOME") ?: System.getProperty("user.home")
  if (home.isNullOrEmpty()) {
    return ""
  }
  return Path.of(home, ".guard-agent", "install-id").toString()
}
