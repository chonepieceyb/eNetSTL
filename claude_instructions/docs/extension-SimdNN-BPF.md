# SimdNN-BPF 扩展设计文档

## 1. 概述

本文档概述了使用 SIMD 指令扩展 eNetSTL 的新模块的设计和开发框架，用于加速 eBPF 中的神经网络推理。该设计灵感来自论文《使用 eBPF 在内核中实现神经网络的实时入侵检测和防御》，旨在通过 SIMD 优化提高性能。

## 2. 背景

### 2.1 当前 eNetSTL 架构
- eNetSTL 为 eBPF 程序提供内核空间数据结构
- 目前支持时间轮、跳表和哈希表
- 使用可加载内核模块（LKM）扩展内核功能
- 提供 eBPF 内核代码和用户空间交互机制

### 2.2 eNetSTL 中的 SIMD 能力
- 当前 SIMD 使用仅限于哈希操作（xxhash 与 AVX2）
- 证明了在内核空间使用 SIMD 指令的可行性
- 为实现 SIMD 加速神经网络提供了基础

## 3. SimdNN-BPF 模块设计

### 3.1 核心架构

```
┌─────────────────────────────────────────────────────────┐
│                     用户空间                            │
├─────────────────────────────────────────────────────────┤
│                 eBPF 程序                              │
├─────────────────────────────────────────────────────────┤
│              SimdNN-BPF LKM 模块                      │
│  ┌─────────────────┐  ┌─────────────────┐              │
│  │   神经网络引擎   │  │   SIMD 工具     │              │
│  │                 │  │                 │              │
│  │ • 全连接层      │  │ • AVX2/AVX512   │              │
│  │ • 激活函数      │  │ • 向量操作      │              │
│  │ • 卷积操作      │  │ • 内存管理      │              │
│  │ • 池化操作      │  │                 │              │
│  └─────────────────┘  └─────────────────┘              │
├─────────────────────────────────────────────────────────┤
│                     内核空间                            │
└─────────────────────────────────────────────────────────┘
```

### 3.2 关键组件

#### 3.2.1 神经网络引擎
- **全连接层实现**：SIMD 加速的矩阵乘法
- **激活函数**：使用向量指令优化的 ReLU、Sigmoid、Tanh
- **卷积操作**：SIMD 优化的 2D 卷积
- **池化操作**：SIMD 加速的最大池化和平均池化

#### 3.2.2 SIMD 工具
- **向量操作**：基本 SIMD 操作（加法、乘法等）
- **内存管理**：对齐 SIMD 数据的高效内存分配
- **指令调度**：运行时检测和最优指令选择

#### 3.2.3 eBPF 接口
- **自定义映射类型**：神经网络模型存储和推理映射
- **辅助函数**：eBPF 可调用的神经网络操作函数
- **数据结构**：神经网络参数的高效数据结构

### 3.3 文件结构

```
eNetSTL/src/
├── LKMs/SimdNN/
│   ├── Makefile
│   ├── simdnn_bpf.c          # 主要 LKM 实现
│   ├── simdnn_engine.c       # 神经网络引擎
│   ├── simdnn_ops.c          # SIMD 操作
│   ├── simdnn_dense.c        # 全连接层实现
│   ├── simdnn_conv.c         # 卷积实现
│   ├── simdnn_activation.c   # 激活函数
│   └── simdnn_utils.h        # 头文件定义
├── bpf_kern/SimdNN/
│   ├── simdnn_kern.h         # eBPF 内核头文件
│   ├── simdnn_kern.c         # eBPF 内核实现
│   └── models/               # 预训练模型定义
└── c/SimdNN/
    ├── simdnn_user.c         # 用户空间接口
    └── simdnn_test.c         # 测试工具
```

## 4. 技术实现

### 4.1 SIMD 指令集支持

```c
// 运行时 CPU 特征检测
struct simdnn_cpu_features {
    bool has_avx512f;
    bool has_avx2;
    bool has_avx;
    bool has_sse4_2;
    bool has_popcnt;
};

// 函数指针调度表
struct simdnn_ops {
    void (*matmul_avx512)(const float *A, const float *B, float *C,
                         int M, int N, int K);
    void (*matmul_avx2)(const float *A, const float *B, float *C,
                       int M, int N, int K);
    void (*matmul_sse)(const float *A, const float *B, float *C,
                      int M, int N, int K);
};
```

### 4.2 全连接层实现

```c
struct simdnn_dense_layer {
    float *weights;
    float *biases;
    int input_size;
    int output_size;
    enum simdnn_activation activation;
};

// SIMD 优化的矩阵乘法
static void simdnn_dense_forward_avx2(
    const struct simdnn_dense_layer *layer,
    const float *input,
    float *output
) {
    // 使用 8 宽向量操作的 AVX2 实现
    for (int i = 0; i < layer->output_size; i += 8) {
        __m256 sum = _mm256_setzero_ps();

        for (int j = 0; j < layer->input_size; j += 8) {
            __m256 in_vec = _mm256_load_ps(input + j);
            __m256 weight_vec = _mm256_load_ps(layer->weights + i * layer->input_size + j);
            sum = _mm256_fmadd_ps(in_vec, weight_vec, sum);
        }

        _mm256_store_ps(output + i, sum);
    }
}
```

### 4.3 eBPF 映射集成

```c
// 神经网络推理的自定义映射类型
struct bpf_map_ops simdnn_inference_ops = {
    .map_alloc_check = simdnn_map_alloc_check,
    .map_alloc = simdnn_map_alloc,
    .map_free = simdnn_map_free,
    .map_lookup_elem = simdnn_lookup_elem,
    .map_update_elem = simdnn_update_elem,
    .map_delete_elem = simdnn_delete_elem,
};

// eBPF 推理辅助函数
__bpf_kfunc int bpf_simdnn_inference(
    struct bpf_map *map,
    const void *input,
    void *output,
    u32 input_size,
    u32 output_size
) {
    // 神经网络推理实现
}
```

### 4.4 激活函数

```c
// SIMD 优化的 ReLU 激活函数
static inline void simdnn_relu_avx2(float *data, int size) {
    int simd_size = size & ~7;

    // 一次处理 8 个元素
    for (int i = 0; i < simd_size; i += 8) {
        __m256 vec = _mm256_load_ps(data + i);
        __m256 zero = _mm256_setzero_ps();
        vec = _mm256_max_ps(vec, zero);
        _mm256_store_ps(data + i, vec);
    }

    // 处理剩余元素
    for (int i = simd_size; i < size; i++) {
        data[i] = data[i] > 0 ? data[i] : 0;
    }
}
```

## 5. 内存管理

### 5.1 对齐内存分配

```c
// SIMD 对齐内存分配器
static void *simdnn_aligned_alloc(size_t size, size_t alignment) {
    void *ptr;
    int ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0) {
        return NULL;
    }
    return ptr;
}

// 用于高效分配的模型内存池
struct simdnn_memory_pool {
    void *base_addr;
    size_t pool_size;
    size_t used;
    struct mutex lock;
};
```

### 5.2 模型参数存储

```c
// 神经网络模型结构
struct simdnn_model {
    char name[64];
    int version;
    int num_layers;
    struct simdnn_layer **layers;
    struct simdnn_memory_pool *param_pool;
    struct simdnn_memory_pool *activation_pool;
};

// 层接口
struct simdnn_layer {
    enum simdnn_layer_type type;
    void (*forward)(struct simdnn_layer *layer, const float *input, float *output);
    void (*backward)(struct simdnn_layer *layer, const float *input, const float *output, float *grad_input);
    void *params;
    void *grads;
};
```

## 6. 性能优化

### 6.1 循环展开和向量化

```c
// 循环展开优化示例
#define UNROLL_FACTOR 8
#pragma GCC unroll UNROLL_FACTOR
for (int i = 0; i < size; i += UNROLL_FACTOR) {
    // 一次处理 UNROLL_FACTOR 个元素
}
```

### 6.2 缓存优化

```c
// 缓存友好的分块矩阵乘法
static void simdnn_matmul_blocked(
    const float *A, const float *B, float *C,
    int M, int N, int K, int block_size
) {
    for (int i = 0; i < M; i += block_size) {
        for (int j = 0; j < N; j += block_size) {
            for (int k = 0; k < K; k += block_size) {
                // 处理块
                simdnn_matmul_block(A, B, C, i, j, k, block_size, M, N, K);
            }
        }
    }
}
```

## 7. eBPF 集成

### 7.1 自定义映射定义

```c
// SimdNN 推理映射
struct simdnn_inference_map {
    struct bpf_map map;
    struct simdnn_model *model;
    struct bpf_mem_alloc ma;
    struct simdnn_memory_pool *input_pool;
    struct simdnn_memory_pool *output_pool;
};
```

### 7.2 辅助函数注册

```c
// 注册 SIMDNN 辅助函数
BTF_SET8_START(simdnn_kfunc_ids)
BTF_ID_FLAGS(func, bpf_simdnn_inference)
BTF_ID_FLAGS(func, bpf_simdnn_load_model)
BTF_ID_FLAGS(func, bpf_simdnn_get_model_info)
BTF_SET8_END(simdnn_kfunc_ids)

static const struct btf_kfunc_id_set simdnn_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &simdnn_kfunc_ids,
};
```

## 8. 测试框架

### 8.1 单元测试

```c
// 单元测试结构
struct simdnn_test_case {
    const char *name;
    void (*test_func)(void);
    bool expected_result;
};

// 各组件的测试用例
static struct simdnn_test_case simdnn_test_cases[] = {
    {"dense_layer_forward", test_dense_layer_forward, true},
    {"relu_activation", test_relu_activation, true},
    {"conv2d_forward", test_conv2d_forward, true},
    {"max_pooling", test_max_pooling, true},
    {NULL, NULL, false}
};
```

### 8.2 性能基准测试

```c
// 性能测量
struct simdnn_benchmark {
    const char *name;
    void (*benchmark_func)(void);
    int iterations;
    double avg_time_ms;
};

static struct simdnn_benchmark simdnn_benchmarks[] = {
    {"matmul_256x256", benchmark_matmul_256x256, 1000, 0},
    {"conv2d_3x3_32ch", benchmark_conv2d_3x3_32ch, 1000, 0},
    {"relu_1024", benchmark_relu_1024, 10000, 0},
    {NULL, NULL, 0, 0}
};
```

## 9. 安全考虑

### 9.1 输入验证

```c
// 验证神经网络输入
static int simdnn_validate_input(
    const struct simdnn_model *model,
    const void *input,
    u32 input_size
) {
    if (!model || !input) {
        return -EINVAL;
    }

    if (input_size != model->input_size * sizeof(float)) {
        return -EINVAL;
    }

    return 0;
}
```

### 9.2 内存安全

```c
// 神经网络操作的边界检查
static int simdnn_check_bounds(
    const struct simdnn_model *model,
    const float *input,
    float *output
) {
    if (!input || !output) {
        return -EINVAL;
    }

    // 检查数组边界
    if (!access_ok(input, model->input_size * sizeof(float)) ||
        !access_ok(output, model->output_size * sizeof(float))) {
        return -EFAULT;
    }

    return 0;
}
```

## 10. 开发路线图

### 第一阶段：基础构建（第 1-2 周）
- [ ] SIMD 工具函数实现
- [ ] 基本内存管理系统
- [ ] 核心数据结构定义
- [ ] 构建系统配置

### 第二阶段：核心操作（第 3-4 周）
- [ ] SIMD 全连接层实现
- [ ] 激活函数优化
- [ ] 基本 eBPF 接口
- [ ] 核心操作单元测试

### 第三阶段：高级功能（第 5-6 周）
- [ ] 卷积操作实现
- [ ] 池化操作
- [ ] 高级 eBPF 集成
- [ ] 性能优化

### 第四阶段：集成和测试（第 7-8 周）
- [ ] 端到端集成
- [ ] 性能基准测试
- [ ] 文档完成
- [ ] 最终测试和验证

## 11. 预期性能提升

基于神经网络库中类似的 SIMD 优化：

- **矩阵乘法**：AVX2 提升 4-8 倍，AVX-512 提升 8-16 倍
- **激活函数**：向量指令提升 8-16 倍
- **卷积操作**：SIMD 优化提升 2-4 倍
- **整体推理**：典型神经网络模型提升 3-6 倍

## 12. 结论

SimdNN-BPF 扩展将在 eBPF 生态系统中提供高性能的神经网络推理能力，实现实时入侵检测和其他机器学习应用直接在内核中运行。SIMD 优化方法建立在现有 eNetSTL 基础设施之上，同时提供比标量实现显著的性能改进。

该设计为在 eBPF 中实现 SIMD 加速神经网络提供了全面的基础，仔细考虑了性能、安全性和与现有 eNetSTL 生态系统的集成。