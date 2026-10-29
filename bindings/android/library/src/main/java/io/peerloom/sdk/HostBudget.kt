package io.peerloom.sdk

/** Host-owned copies only; independent of the native resource budget and process RSS. */
internal class HostBudget(val bytes: Long = 134217728L) {
    init {
        require(bytes >= 2097152L)
    }

    private val reserve = maxOf(262144L, bytes / 8)
    private var dataBytes = 0L
    private var criticalBytes = 0L
    private var lifecycleBytes = 0L
    private var dataTickets = 0L
    private var criticalTickets = 0L
    private var connections = 0L
    private var streams = 0L

    @Synchronized
    fun population(connections: Long, streams: Long) {
        require(connections >= 0 && streams >= 0)
        // Validate the complete arithmetic before changing either count.
        limits(connections, streams)
        this.connections = connections
        this.streams = streams
    }

    private fun limits(c: Long, s: Long): Pair<Long, Long> =
        Pair(
            Math.addExact(64L, Math.addExact(Math.multiplyExact(8L, c), Math.multiplyExact(2L, s))),
            Math.addExact(64L, Math.addExact(c, s)),
        )

    @Synchronized
    fun acquire(payloadBytes: Long, critical: Boolean): Ticket =
        acquireInternal(payloadBytes, critical, true)

    @Synchronized
    fun acquireLifecycle(payloadBytes: Long = 256L): Ticket =
        acquireInternal(payloadBytes, true, false, true)

    @Synchronized
    fun acquireUrgentReset(payloadBytes: Long): Ticket =
        acquireInternal(payloadBytes, true, false, false)

    private fun acquireInternal(
        payloadBytes: Long,
        critical: Boolean,
        counted: Boolean,
        lifecycle: Boolean = false,
    ): Ticket {
        require(payloadBytes >= 0)
        val size = Math.addExact(payloadBytes, 256L)
        val limit = limits(connections, streams)
        val used = if (!critical) dataBytes else if (!lifecycle) criticalBytes else lifecycleBytes
        val ceiling =
            if (!critical) bytes - reserve
            else if (!lifecycle) reserve / 2 else reserve - reserve / 2
        val count = if (critical) criticalTickets else dataTickets
        if (
            size > ceiling - used ||
                (counted && count >= if (critical) limit.second else limit.first)
        ) {
            throw PeerloomException(6)
        }
        val ticket = Ticket(this, size, critical, counted, lifecycle)
        if (critical) {
            if (!lifecycle) {
                criticalBytes += size
                if (counted) criticalTickets += 1
            } else {
                lifecycleBytes += size
            }
        } else {
            dataBytes += size
            if (counted) dataTickets += 1
        }
        return ticket
    }

    @Synchronized
    private fun release(size: Long, critical: Boolean, counted: Boolean, lifecycle: Boolean) {
        if (critical) {
            if (!lifecycle) {
                check((!counted || criticalTickets > 0) && criticalBytes >= size)
                if (counted) criticalTickets -= 1
                criticalBytes -= size
            } else {
                check(lifecycleBytes >= size)
                lifecycleBytes -= size
            }
        } else {
            check((!counted || dataTickets > 0) && dataBytes >= size)
            if (counted) dataTickets -= 1
            dataBytes -= size
        }
    }

    @Synchronized
    internal fun usage(): List<Long> =
        listOf(dataTickets, criticalTickets, dataBytes, criticalBytes + lifecycleBytes)

    internal class Ticket(
        private val owner: HostBudget,
        private val size: Long,
        private val critical: Boolean,
        private val counted: Boolean,
        private val lifecycle: Boolean,
    ) : AutoCloseable {
        private var closed = false

        @Synchronized
        fun permits(length: Long): Boolean = !closed && length >= 0 && length <= size - 256L

        @Synchronized
        override fun close() {
            if (!closed) {
                closed = true
                owner.release(size, critical, counted, lifecycle)
            }
        }
    }
}
