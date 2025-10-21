// simdnn_user.c
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <getopt.h>
#include <ifaddrs.h>

#include "common_user.h"
#include "../bpf_skel/simdnn.bpf.skel.h"
#include "../../bpf_kern/nn-ids-enetstl/mlp_params.bpf.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

// 动态获取第一个非回环网卡名称
static char* get_first_non_loopback_interface()
{
    struct ifaddrs *ifaddrs_ptr, *ifa;
    static char interface_name[IF_NAMESIZE] = {0};

    if (getifaddrs(&ifaddrs_ptr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        // 跳过回环接口
        if (strcmp(ifa->ifa_name, "lo") == 0) {
            continue;
        }

        // 检查接口是否处于活动状态
        if (!(ifa->ifa_flags & IFF_UP)) {
            continue;
        }

        // 检查是否是网络接口（有IP地址）
        if (ifa->ifa_addr->sa_family == AF_INET ||
            ifa->ifa_addr->sa_family == AF_INET6) {

            // 检查接口是否支持XDP
            unsigned int ifindex = if_nametoindex(ifa->ifa_name);
            if (ifindex > 0) {
                strncpy(interface_name, ifa->ifa_name, IF_NAMESIZE - 1);
                interface_name[IF_NAMESIZE - 1] = '\0';
                freeifaddrs(ifaddrs_ptr);
                return interface_name;
            }
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return NULL;
}

/* 仅初始化从 fc1 开始的层；不触碰 input_buffer（由 kfunc 实参提供） */
static int setup_model_map(struct bpf_map *model_map)
{
    __u32 key = 0;
    struct model model = (struct model){0};

    /* fc1: N0 -> N1 */
    model.fc1.comm.type = ENETSTL_FC_LAYER;
    model.fc1.comm.next_layer_off = (int)offsetof(struct model, relu1);
    model.fc1.parm.in_features = N0;
    model.fc1.parm.out_features = N1;
    for (int i = 0; i < N1; i++)
    {
        for (int j = 0; j < N0; j++)
            model.fc1.weights[i][j] = layer_0_weight[i * N0 + j];
    }

    /* relu1 -> fc2 */
    model.relu1.comm.type = ENETSTL_RELU_LAYER;
    model.relu1.comm.next_layer_off = (int)offsetof(struct model, fc2);

    /* fc2: N1 -> N2 */
    model.fc2.comm.type = ENETSTL_FC_LAYER;
    model.fc2.comm.next_layer_off = (int)offsetof(struct model, relu2);
    model.fc2.parm.in_features = N1;
    model.fc2.parm.out_features = N2;
    for (int i = 0; i < N2; i++)
    {
        for (int j = 0; j < N1; j++)
            model.fc2.weights[i][j] = layer_1_weight[i * N1 + j];
    }

    /* relu2 -> fc_out -> output_buffer(终止) */
    model.relu2.comm.type = ENETSTL_RELU_LAYER;
    model.relu2.comm.next_layer_off = (int)offsetof(struct model, fc_out);

    model.fc_out.comm.type = ENETSTL_FC_LAYER;
    model.fc_out.comm.next_layer_off = (int)offsetof(struct model, output_buffer);
    model.fc_out.parm.in_features = N2;
    model.fc_out.parm.out_features = N3;
    for (int i = 0; i < N3; i++)
    {
        for (int j = 0; j < N2; j++)
            model.fc_out.weights[i][j] = layer_2_weight[i * N2 + j];
    }

    model.output_buffer.comm.type = ENETSTL_OUTPUT_LAYER;
    model.output_buffer.comm.next_layer_off = 0;

    return bpf_map_update_elem(bpf_map__fd(model_map), &key, &model, BPF_ANY);
}

/* 新增：初始化 input_map[0]，作为推理输入缓冲（6 个 int） */
static int setup_input_map(struct bpf_map *input_map)
{
    __u32 key = 0;

    /* 默认给 6 个维度置 0；按需改成你的默认输入 */
    int init_attr[6] = {0, 0, 0, 0, 0, 0};

    /* 如果你的内核里该 map 定义成 PERCPU_ARRAY，也可以用 bpf_map_update_elem 同样写入每核默认值 */
    return bpf_map_update_elem(bpf_map__fd(input_map), &key, init_attr, BPF_ANY);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--dev IFNAME]\n", prog);
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;  // 初始为NULL，支持动态检测
    int ifindex = 0;
    int err = 0;

    /* 仅支持 --dev <IFNAME>，不接受位置参数 */
    static const struct option long_opts[] = {
        {"dev", required_argument, NULL, 'd'},
        {0, 0, 0, 0}};
    int opt, longidx;
    while ((opt = getopt_long(argc, argv, "", long_opts, &longidx)) != -1)
    {
        switch (opt)
        {
        case 'd':
            ifname = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (optind < argc)
    { // 有多余参数
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        usage(argv[0]);
        return 1;
    }

    // 如果没有指定网卡，则动态检测第一个非回环网卡
    if (ifname == NULL) {
        ifname = get_first_non_loopback_interface();
        if (ifname == NULL) {
            fprintf(stderr, "Failed to find a suitable network interface (non-loopback, active)\n");
            fprintf(stderr, "Please specify one manually using --dev <IFNAME>\n");
            return 1;
        }
        printf("Auto-detected network interface: %s\n", ifname);
    } else {
        printf("Using specified network interface: %s\n", ifname);
    }

    libbpf_set_print(libbpf_print_fn);

    // 提高 memlock 限额，避免“memlock limit”报错
    struct rlimit rlim = {.rlim_cur = 512U * 1024U * 1024U, .rlim_max = 512U * 1024U * 1024U};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

    // 打开并加载
    struct simdnn_bpf *skel = simdnn_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    err = simdnn_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 加载完成后再写 model_map（不初始化 input_buffer）
    err = setup_model_map(skel->maps.model_map);
    if (err)
    {
        fprintf(stderr, "Failed to setup model map: %d\n", err);
        goto cleanup;
    }

    // 写input_map
    err = setup_input_map(skel->maps.input_map);
    if (err)
    {
        fprintf(stderr, "Failed to setup input map: %d\n", err);
        goto cleanup;
    }

    // 裸 attach：进程退出后仍附着
    ifindex = if_nametoindex(ifname);
    if (!ifindex)
    {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n", ifname, strerror(errno));
        err = -errno;
        goto cleanup;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_main),
                         XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err)
    {
        fprintf(stderr, "Failed to attach XDP to %s: %d\n", ifname, err);
        goto cleanup;
    }

    printf("SimdNN-BPF XDP attached on %s.\n", ifname);
    printf("Program exits now; XDP stays attached.\n");
    printf("To detach later: sudo bpftool net detach xdp dev %s\n", ifname);

cleanup:
    simdnn_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
