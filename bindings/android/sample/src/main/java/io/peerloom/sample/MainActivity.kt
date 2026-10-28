package io.peerloom.sample

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/** No embedded keys/grants or automatic production connection. */
class MainActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(
            TextView(this).apply {
                text =
                    "Peerloom / 设备互联\n\nConfigure your HTTPS origin and application ID, then use PeerloomSdk.create → start/register → connect.\n\n请由宿主安全提供服务器与授权信息；示例不内嵌凭证。"
                setPadding(32, 32, 32, 32)
            }
        )
    }
}
