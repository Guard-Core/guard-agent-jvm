package com.guardcore.agent

/**
 * The context.Context analog for the blocking agent surface: a cancellation token with an optional
 * deadline. sendEvent's OverflowBlock policy and the retry sleeps observe it exactly like the Go
 * code observes ctx.Done().
 */
public class AgentContext
private constructor(
    private val deadlineNanos: Long,
    private val cancelable: Boolean,
) {
  @Volatile private var canceled: Boolean = false

  internal fun cancel() {
    if (cancelable) {
      canceled = true
    }
  }

  /** Go ctx.Done(): true once canceled or past the deadline. */
  public fun isDone(): Boolean = canceled || System.nanoTime() >= deadlineNanos

  /** Go ctx.Err(). */
  public fun err(): ContextDone =
      ContextDone(if (canceled) "context canceled" else "context deadline exceeded")

  public companion object {
    /** The background sentinel: never carries a deadline and cannot be canceled. */
    @JvmField public val NONE: AgentContext = AgentContext(Long.MAX_VALUE, cancelable = false)

    /** Go context.WithTimeout. */
    public fun withTimeout(millis: Long): AgentContext =
        AgentContext(System.nanoTime() + millis * 1_000_000, cancelable = true)

    /** Go context.WithCancel (tests drive cancellation directly). */
    public fun withCancel(): AgentContext = AgentContext(Long.MAX_VALUE, cancelable = true)
  }
}

/** The ctx.Err() analog, matched with matchesKind(ErrorKind.CONTEXT_DONE). */
public class ContextDone(
    message: String,
) : RuntimeException(message)
