#pragma once
#include <linux/stddef.h>
int simdnn_analyze_and_infer(void *m, size_t model_size, void *attr, size_t attr_size);