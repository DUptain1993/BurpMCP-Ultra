package com.burpmcp.ultra.transport

import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Verifies the recovery TRIGGER for the SSE back-pressure hang ([runWithSendTimeout], used by
 * TimeoutSseTransport.send). The recovery MECHANISM (cancelling the session job → shared
 * byte-channel cancelled → parked flush() resumes throwing → per-session Mutex released) is Ktor/
 * SDK behaviour verified at the bytecode level; this test pins the trigger we own.
 */
class SendTimeoutTest {

    @Test fun `completes within the deadline - returns value, session left alive`() = runTest {
        val sessionJob = Job()
        var timedOut = false
        val result = runWithSendTimeout(60_000, sessionJob, onTimeout = { timedOut = true }) { "ok" }
        assertEquals("ok", result)
        assertFalse(timedOut, "onTimeout must not fire on a fast send")
        assertTrue(sessionJob.isActive, "a healthy session must NOT be torn down")
    }

    @Test fun `exceeds the deadline - cancels the session job and rethrows`() = runTest {
        val sessionJob = Job()
        var timedOut = false
        assertFailsWith<TimeoutCancellationException> {
            // awaitCancellation() never completes on its own -> models a wedged flush().
            runWithSendTimeout(50, sessionJob, onTimeout = { timedOut = true }) { awaitCancellation() }
        }
        assertTrue(timedOut, "onTimeout must fire so the operator sees the stall")
        assertTrue(sessionJob.isCancelled, "the SSE session job MUST be cancelled to recover the wedge")
    }
}
