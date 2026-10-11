package com.guardcore.agent

import java.util.logging.Logger

/**
 * Port of guard-agent-go `error_hook.go`: the OnError failure-hook stages and the fire helper,
 * matching the Python agent's on_error stage names exactly.
 */
public object ErrorHookStages {
  /**
   * Fires when a batch send ultimately fails: retry attempts exhausted, a 413 that persists even as
   * a singleton, or a permanent 4xx rejection that durably drops the batch.
   */
  public const val TRANSPORT_SEND: String = "transport_send"

  /** Fires when batch serialization or AES-GCM encryption fails on the encrypted-ingest path. */
  public const val ENCRYPTION: String = "encryption"

  /** Fires when an events flush cycle fails and the batch is requeued. */
  public const val FLUSH_EVENTS: String = "flush_events"

  /** Fires when a metrics flush cycle fails and the batch is requeued. */
  public const val FLUSH_METRICS: String = "flush_metrics"
}

/**
 * error_hook.go `fireErrorHook`: invokes the user's on_error callback, if any, without ever letting
 * it take the agent down: a throwing hook is recovered and logged. Best effort by contract.
 */
internal fun fireErrorHook(
    hook: OnErrorHook?,
    logger: Logger,
    stage: String,
    err: Throwable?,
    context: Map<String, Any?>,
) {
  if (hook == null) {
    return
  }
  try {
    hook.onError(stage, err, context)
  } catch (panic: Throwable) {
    logger.warning(
        "guardagent: on_error hook raised while handling '$stage': $panic",
    )
  }
}
