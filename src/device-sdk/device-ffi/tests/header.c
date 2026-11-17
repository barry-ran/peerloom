/* MIT: native C11 header/linkage check; C++ lifecycle covers actual create/shutdown. */
#include "device_sdk.h"
_Static_assert(sizeof(((dp_event *)0)->request_id) == 8, "request ABI");
_Static_assert(offsetof(dp_event, payload) == 32, "payload ABI");
_Static_assert(DP_CHANNEL_STATS == 7, "channel stats operation");
_Static_assert(DP_CAP_CHANNEL_STATS == UINT64_C(1024), "channel stats capability");
int main(void) {
    const uint64_t required = UINT64_C(1023) | DP_CAP_CHANNEL_STATS;
    return dp_abi_version() == 2 && (dp_capabilities() & required) == required ? 0 : 1;
}
