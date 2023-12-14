#ifndef EBPF_DEMO_COMMON_H
#define EBPF_DEMO_COMMON_H

#include "vmlinux.h"
#include <bpf_helpers.h>

#ifndef LOG_LEVEL
#define LOG_LEVEL 2
#endif 

#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0 

// #define COLOR_RED "\033[0;31m"
// #define COLOR_GREEN "\033[0;32m"
// #define COLOR_YELLOW "\033[1;33m"
// #define COLOR_ORIGIN "\033[0;33m"
// #define COLOR_OFF "\033[0m" 

/*
*DEBUG: LEVEL=4
*INFO: LEVEL=3
*WARN: LEVEL=2
*ERROR: LEVEL=1
*/

#if LOG_LEVEL >= LOG_LEVEL_DEBUG			
	#define log_debug(FMT, ...)				\
	({										\
		bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_debug(fmt, ...)	 ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO			
	#define log_info(FMT, ...)											\
	({																	\
		bpf_printk("[INFO]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_info(fmt, ...)	 ({})									
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN			
	#define log_warn(FMT, ...)											\
	({																	\
		bpf_printk("[WARN]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_warn(fmt, ...)	 ({})									
#endif

#if LOG_LEVEL >= LOG_LEVEL_ERROR		
	#define log_error(FMT, ...)											\
	({																	\
		bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__);						\
	})										
#else
	#define log_error(fmt, ...)	 ({})									
#endif

#endif 