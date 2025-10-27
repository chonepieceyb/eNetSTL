TODO: this scripts generates code snippets by inheriting from CommonSkeleton class in skeleton

### for skel_bpf_header_sec
parms: 
    none
generate:

```c
#include "../common.h"

/* for statistics */
char _license[] SEC("license") = "GPL";
PACKET_COUNT_MAP_DEFINE
```