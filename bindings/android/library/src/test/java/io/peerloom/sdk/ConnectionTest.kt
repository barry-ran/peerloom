package io.peerloom.sdk

import java.util.concurrent.Executor
import org.junit.Assert.*
import org.junit.Test

class ConnectionTest {
    // 仅测试装配使用反射；不启动 JNI，也不向产品 API 增加测试入口。
    private fun sdk(listener: (Event) -> Unit = {}): PeerloomSdk {
        val constructor =
            PeerloomSdk::class.java.declaredConstructors.single { it.parameterCount == 4 }
        constructor.isAccessible = true
        return constructor.newInstance(
            IdentityStorage { error("本测试不访问存储") },
            listener,
            Executor { it.run() },
            HostBudget(),
        ) as PeerloomSdk
    }

    @Test
    fun duplicateWrappersCorrelateWithoutChangingObjectEquality() {
        val sdk = sdk()
        val first = Connection(sdk, 41)
        val duplicate = Connection(sdk, 41)
        assertTrue(first.sameConnection(first))
        assertTrue(first.sameConnection(duplicate))
        assertTrue(duplicate.sameConnection(first))
        assertNotSame(first, duplicate)
        assertNotEquals(first, duplicate)
        assertFalse(first.sameConnection(Connection(sdk, 42)))
    }

    @Test
    fun equalNumericHandlesFromDifferentSdkInstancesDoNotCorrelate() {
        val first = Connection(sdk(), 41)
        val other = Connection(sdk(), 41)
        assertFalse(first.sameConnection(other))
        assertFalse(other.sameConnection(first))
    }

    @Test
    fun invalidConnectionsStillCorrelateButReplacementDoesNot() {
        val sdk = sdk()
        val old = Connection(sdk, 41)
        val lateClosed = Connection(sdk, 41)
        val replacement = Connection(sdk, 42)
        // SDK 句柄为零，模拟释放后状态；isValid 在 Kotlin 层短路，不调用 JNI。
        assertFalse(old.isValid())
        assertFalse(lateClosed.isValid())
        assertTrue(old.sameConnection(lateClosed))
        assertFalse(old.sameConnection(replacement))
    }

    @Test
    fun actualHostDispatchCreatesDistinctWrappersForLateClosedEvents() {
        val events = mutableListOf<Event>()
        val sdk = sdk { events.add(it) }
        val callback =
            PeerloomSdk::class
                .java
                .getDeclaredMethod(
                    "onNativeEvent",
                    Long::class.javaPrimitiveType,
                    Int::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    Int::class.javaPrimitiveType,
                    ByteArray::class.java,
                )
        callback.isAccessible = true
        for (handle in listOf(41L, 41L, 42L, 0L)) {
            callback.invoke(sdk, 0L, 7, 0L, handle, 0L, 0, byteArrayOf())
        }
        assertEquals(4, events.size)
        val first = events[0].connection!!
        val duplicate = events[1].connection!!
        assertNotSame(first, duplicate)
        assertFalse(first.isValid())
        assertTrue(first.sameConnection(duplicate))
        assertFalse(first.sameConnection(events[2].connection!!))
        assertNull(events[3].connection)
    }
}
