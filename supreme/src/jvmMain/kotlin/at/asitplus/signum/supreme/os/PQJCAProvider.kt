package at.asitplus.signum.supreme.os
import iaik.security.pq.provider.IaikPq
import java.util.concurrent.atomic.AtomicBoolean

object PQJCAProviderInit {
    private val installed = AtomicBoolean(false)

    fun ensureInstalled() {
        if (installed.compareAndSet(false, true)) {
            IaikPq.addAsProvider()
        }
    }
}
