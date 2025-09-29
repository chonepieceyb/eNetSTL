#ifndef EBPF_ENETSTL_USER_CONFIG_H
#define EBPF_ENETSTL_USER_CONFIG_H

//TODO: modify cmakes to andd compilation option by specify XDP_IF and XDP_MODE
//check all src/c/* to update current programs to use these macros

#ifndef XDP_IF
#define XDP_IF "ens2f0"
#endif

#ifndef XDP_MODE
#define XDP_MODE  XDP_FLAGS_SKB_MODE
#endif 

#endif