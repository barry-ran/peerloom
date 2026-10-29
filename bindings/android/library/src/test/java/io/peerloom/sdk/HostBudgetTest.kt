package io.peerloom.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HostBudgetTest {
    @Test
    fun fiveHundredReadsAndManagementRemainIndependent() {
        val budget = HostBudget()
        budget.population(500, 500)
        val reads = (1..500).map { budget.acquire(65536, false) }
        val close = budget.acquire(256, true)
        budget.population(0, 0)
        assertThrows(PeerloomException::class.java) { budget.acquire(1, false) }
        reads.forEach {
            it.close()
            it.close()
        }
        close.close()
        assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
    }

    @Test
    fun byteExhaustionDoesNotBorrowCriticalReserve() {
        val budget = HostBudget(2097152)
        val data = budget.acquire(1834752, false)
        assertThrows(PeerloomException::class.java) { budget.acquire(1, false) }
        val critical = budget.acquire(130816, true)
        assertThrows(PeerloomException::class.java) { budget.acquireUrgentReset(0) }
        assertThrows(PeerloomException::class.java) { budget.acquire(1, true) }
        data.close()
        critical.close()
        assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
    }

    @Test
    fun overflowDoesNotChangePopulationOrAllocate() {
        val budget = HostBudget()
        assertThrows(ArithmeticException::class.java) { budget.population(Long.MAX_VALUE, 0) }
        val tickets = (1..64).map { budget.acquire(0, false) }
        assertThrows(PeerloomException::class.java) { budget.acquire(0, false) }
        tickets.forEach { it.close() }
    }

    @Test
    fun pausedConsumerCanRetainReadyWhileFiveHundredParentsClose() {
        val budget = HostBudget()
        budget.population(500, 500)
        val ready = (1..1000).map { budget.acquire(128, false) }
        val reads = (1..500).map { budget.acquire(65536, false) }
        val terminal = (1..1000).map { budget.acquire(0, true) }
        // Actual callers retain population until consuming lifecycle records.
        terminal.forEach { it.close() }
        budget.population(0, 0)
        ready.forEach { it.close() }
        reads.forEach { it.close() }
        assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
    }

    @Test
    fun concurrentDoubleReleaseReturnsEveryByteExactlyOnce() {
        val budget = HostBudget()
        budget.population(500, 500)
        val tickets = (1..500).map { budget.acquire(1024, false) }
        val executor = java.util.concurrent.Executors.newFixedThreadPool(4)
        try {
            val tasks =
                tickets.flatMap { ticket ->
                    listOf(executor.submit { ticket.close() }, executor.submit { ticket.close() })
                }
            tasks.forEach { it.get(5, java.util.concurrent.TimeUnit.SECONDS) }
            assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun lifecycleReservationsDoNotConsumeOperationCountSlots() {
        val budget = HostBudget()
        budget.population(1, 0)
        val lifecycles = (1..1000).map { budget.acquireLifecycle() }
        val management = (1..65).map { budget.acquire(0, true) }
        assertThrows(PeerloomException::class.java) { budget.acquire(0, true) }
        lifecycles.forEach { it.close() }
        management.forEach { it.close() }
        assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
    }

    @Test
    fun lifecycleBytesCannotConsumeManagementReserve() {
        val budget = HostBudget(2097152)
        val lifecycles = (1..256).map { budget.acquireLifecycle() }
        assertThrows(PeerloomException::class.java) { budget.acquireLifecycle() }
        val close = budget.acquire(130816, true)
        close.close()
        lifecycles.forEach { it.close() }
        assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
    }

    @Test
    fun retainedCloseCreditsAfterShrinkDoNotBlockUrgentReset() {
        val budget = HostBudget()
        budget.population(65, 0)
        val closes = (1..65).map { budget.acquire(256, true) }
        budget.population(0, 0)
        assertThrows(PeerloomException::class.java) { budget.acquire(0, true) }
        val reset = budget.acquireUrgentReset(256)
        reset.close()
        assertEquals(65L, budget.usage()[1])
        closes.forEach { it.close() }
        assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
    }
}
