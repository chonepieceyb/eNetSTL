#pragma once 
#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

struct fc_layer {

};

int bpf_nm_inference(void *model, int model_size__sz,
								 void *attr, int attr_size__sz)