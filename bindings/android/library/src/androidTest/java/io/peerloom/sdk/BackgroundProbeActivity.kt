package io.peerloom.sdk

import android.app.Activity
import java.util.concurrent.atomic.AtomicInteger

/** Test-APK-only lifecycle probe; never a production UI or background-service claim. */
class BackgroundProbeActivity : Activity() {
    override fun onResume() {
        super.onResume()
        resumes.incrementAndGet()
    }

    override fun onStop() {
        stops.incrementAndGet()
        super.onStop()
    }

    companion object {
        val resumes = AtomicInteger(0)
        val stops = AtomicInteger(0)
    }
}
