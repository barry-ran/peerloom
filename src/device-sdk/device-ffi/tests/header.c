/* MIT: native C11 header/linkage check; C++ lifecycle covers actual create/shutdown. */
#include "device_sdk.h"
_Static_assert(sizeof(((dp_event *)0)->request_id) == 8, "request ABI");
_Static_assert(offsetof(dp_event, payload) == 32, "payload ABI");
int main(void) { return dp_abi_version() == 1 && dp_capabilities() == 511 ? 0 : 1; }
