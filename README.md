# eNetSTL

eNetSTL 源码仓库。

## 目录结构

```
├── src                     # 网络功能
│   ├── bpf_kern            # eBPF 程序
│   ├── c                   # 用户态 C 程序
│   └── python              # Python 程序
├── LKM                     # 内核模块
│   ├── bpf_cmp_alg_simd    # SIMD 并行比较
│   ├── bpf_hash_alg_simd   # SIMD 并行哈希
│   └── ...
├── deps                    # 依赖
└── scripts                 # 工具脚本
```

## 构建与使用

### 构建并加载内核模块

以 `bpf_hash_alg_simd`（SIMD 并行哈希）模块为例，

1. 进入相应模块目录，构建内核模块：

   ```bash
   cd LKM/bpf_hash_alg_simd
   make GCC_VERSION=<GCC 版本>
   ```

2. 加载内核模块：

   ```bash
   sudo insmod bpf_hash_alg_simd.ko
   ```

### 构建并加载网络功能

1. 将 Linux 内核源代码下载（或链接到）到 `linux/` 目录下；

2. 编译 libbpf 和 bpftool：

   ```bash
   # 编译 libbpf
   make -C ./linux/tools/bpf/libbpf
   # 编译 bpftool
   make -C ./linux/tools/bpf/bpftool
   ```

3. 生成 `vmlinux.h`：

   ```bash
   ./scripts/gen_vmlinux_h.h
   ```

4. 更改相应网络功能加载时绑定的网卡，如对于 VBF，可修改其对应用户态程序源码 [`src/c/member_vbf_user.c`](https://github.com/chonepieceyb/ebpf_dp_data_structure/blob/main/src/c/member_vbf_user.c)；

5. 构建网络功能 eBPF 与用户态程序：

   ```bash
   mkdir -p build
   cd build
   cmake -DUSE_HYPERCOM=on -DUSE_STATIC=on ..
   make clean && make -j$(nproc)
   ```

6. 构建完成后，用户态控制程序（通过 BPF skeleton 已包含 BPF 程序）在 `bin/` 目录下，可以直接执行：

   ```bash
   sudo ./bin/member_vbf_user
   ```

7. 用户态控制程序执行后，网络功能已 attach 到指定网卡，可通过脚本 detach：

   ```bash
   ./scripts/detach_xdp.sh "<网卡名>" all 
   ```