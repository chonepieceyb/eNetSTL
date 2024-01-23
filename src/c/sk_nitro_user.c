#include "common.h"

#include <stdlib.h>
#include <bpf/libbpf.h>

#include "bpf_skel/sk_nitro.skel.h"
#include "geo_sampling_pool.h"

#define XDP_IF "ens4np0"

struct pkt_md {
	uint32_t cnt;
	uint32_t geo_sampling_idx;
	uint32_t geo_sampling_array[MAX_GEOSAMPLING_SIZE];
};

int __nitrosketch_after_load(struct sk_nitro *skel)
{
	int ret, cpus;
	size_t metadata_size;
	struct pkt_md *metadata;
	uint32_t zero = 0;

	ret = 0;

	cpus = libbpf_num_possible_cpus();
	if (cpus > ONLINE_CPU_NUM) {
		printf("ONLINE_CPU_NUM %d is smaller than actual CPU count %d\n",
		       ONLINE_CPU_NUM, cpus);
		ret = -EINVAL;
		goto out;
	}
	metadata_size = sizeof(*metadata) * cpus;

	metadata = malloc(metadata_size);
	if (!metadata) {
		printf("Failed to allocate metadata\n");
		ret = -ENOMEM;
		goto out;
	}

	for (int i = 0; i < cpus; i++) {
		metadata[i].cnt = 0;
		metadata[i].geo_sampling_idx = 0;
		for (int j = 0; j < MAX_GEOSAMPLING_SIZE; j++) {
			metadata[i].geo_sampling_array[j] =
				GEO_SAMPLING_POOL[i][j];
		}
	}

	ret = bpf_map__update_elem(skel->maps.metadata, &zero, sizeof(zero),
				   metadata, metadata_size, BPF_ANY);
	if ((ret != 0)) {
		printf("Failed to update metadata map: %d\n", ret);
		goto out_free_metadata;
	}

	printf("Initialized metadata map for %d CPUs\n", cpus);

out_free_metadata:
	free(metadata);
out:
	return ret;
}

int main()
{
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(sk_nitro, XDP_IF, xdp_main,
					  __nitrosketch_after_load,
					  XDP_FLAGS_DRV_MODE)
}
