#pragma once
#include <linux/stddef.h>
#include "common.h"
int simdnn_analyze_and_infer(void *m, size_t model_size, void *attr, size_t attr_size);

/* 每层单独封装kfunc所需内核函数 */
// Relu
void relu_inplace_i32(int *v, int n);

// FC
int fc_forward_i32(const struct fc_layer *fc,
                   const int *x, int x_cap,
                   int *y, int y_cap);