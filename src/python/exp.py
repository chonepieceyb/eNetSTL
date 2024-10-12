#!/usr/bin/python
#
# univmon.py eBPF Countmin Sketch implementation
#
# Copyright (c) Sebastiano Miano <mianosebastiano@gmail.com>
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import re
import shlex
import sys
from typing import Any, Callable, List, Tuple, Union
sys.path.append("..") 
from libbpf import *
from common import *
import time 
import numpy as np 
from bpftools import *
from socket import if_nametoindex
import argparse
from utils import *
import subprocess
import os
from exp_config import *

sys.path.insert(0, '/root/trex/v3.03/automation/trex_control_plane/interactive')
sys.path.insert(0, '/root/trex/v3.03/automation/trex_control_plane/interactive/trex/examples/stl')
sys.path.insert(0, '/root/trex/v3.03/external_libs')
from trex.stl.api import *
from trex.utils.text_opts import format_text

class ExpConfig:
    def __init__(self, *, lat_pps = '1000', bg_no_pps = '0', bg_high_pps = '20000000'):
        #use for test lat_max_pps
        self.lat_pps = lat_pps
        self.bg_no_pps = bg_no_pps
        self.bg_high_pps = bg_high_pps

# List of eBPF programs or (eBPF program, setup hook, teardown hook)s
bpf_prog_list: List[
    Union[str, Tuple[str, Callable[[], Any] | None, Callable[[], Any] | None]]
] = [
    ("enetstl_skiplist_lookup_12_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),
    ("enetstl_skiplist_lookup_13_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),    
    ("enetstl_skiplist_lookup_14_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),
    ("enetstl_skiplist_lookup_15_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),    
    ("enetstl_skiplist_lookup_16_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),
    ("lkm_skiplist_lookup_12_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_lookup_13_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_lookup_14_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_lookup_15_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_lookup_16_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("enetstl_skiplist_ins_del_12_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),
    ("enetstl_skiplist_ins_del_13_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),    
    ("enetstl_skiplist_ins_del_14_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),
    ("enetstl_skiplist_ins_del_15_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),    
    ("enetstl_skiplist_ins_del_16_user", ExpConfig(), lambda: load_lkm("bpf_ptr_structure_lib/bpf_ptr_structure_lib.ko"), lambda: unload_lkm("bpf_ptr_structure_lib")),
    ("lkm_skiplist_ins_del_12_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_ins_del_13_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_ins_del_14_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_ins_del_15_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("lkm_skiplist_ins_del_16_user", ExpConfig(), lambda: load_lkm("exp1-2/skip_list.ko"), lambda: unload_lkm("skip_list")),
    ("ebpf_cuckoo_hash_10_user", ExpConfig()),
    ("ebpf_cuckoo_hash_25_user", ExpConfig()),
    ("ebpf_cuckoo_hash_50_user", ExpConfig()),
    ("ebpf_cuckoo_hash_75_user", ExpConfig()),
    ("ebpf_cuckoo_hash_100_user", ExpConfig()),
    ("enetstl_cuckoo_hash_10_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cuckoo_hash_25_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cuckoo_hash_50_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cuckoo_hash_75_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cuckoo_hash_100_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("lkm_cuckoo_hash_10_user", ExpConfig(), lambda: load_lkm("exp3/cuckoo_hash.ko"), lambda: unload_lkm("cuckoo_hash")),
    ("lkm_cuckoo_hash_25_user", ExpConfig(), lambda: load_lkm("exp3/cuckoo_hash.ko"), lambda: unload_lkm("cuckoo_hash")),
    ("lkm_cuckoo_hash_50_user", ExpConfig(), lambda: load_lkm("exp3/cuckoo_hash.ko"), lambda: unload_lkm("cuckoo_hash")),
    ("lkm_cuckoo_hash_75_user", ExpConfig(), lambda: load_lkm("exp3/cuckoo_hash.ko"), lambda: unload_lkm("cuckoo_hash")),
    ("lkm_cuckoo_hash_100_user", ExpConfig(),lambda: load_lkm("exp3/cuckoo_hash.ko"), lambda: unload_lkm("cuckoo_hash")),
    ("ebpf_sk_nitro_2_user", ExpConfig()),
    ("ebpf_sk_nitro_4_user", ExpConfig()),
    ("ebpf_sk_nitro_6_user", ExpConfig()),
    ("ebpf_sk_nitro_8_user", ExpConfig()),
    ("ebpf_sk_nitro_10_user",  ExpConfig()),
    ("enetstl_sk_nitro_2_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_nitro_4_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_nitro_6_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_nitro_8_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_nitro_10_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("lkm_sk_nitro_2_user", ExpConfig(), lambda: load_lkm("exp4/sk_nitro_2.ko"), lambda: unload_lkm("sk_nitro_2")),
    ("lkm_sk_nitro_4_user", ExpConfig(), lambda: load_lkm("exp4/sk_nitro_4.ko"), lambda: unload_lkm("sk_nitro_4")),
    ("lkm_sk_nitro_6_user", ExpConfig(), lambda: load_lkm("exp4/sk_nitro_6.ko"), lambda: unload_lkm("sk_nitro_6")),
    ("lkm_sk_nitro_8_user", ExpConfig(), lambda: load_lkm("exp4/sk_nitro_8.ko"), lambda: unload_lkm("sk_nitro_8")),
    ("lkm_sk_nitro_10_user", ExpConfig(), lambda: load_lkm("exp4/sk_nitro_10.ko"), lambda: unload_lkm("sk_nitro_10")),
    ("ebpf_sk_cm_2_user",  ExpConfig()),
    ("ebpf_sk_cm_4_user", ExpConfig()),
    ("ebpf_sk_cm_6_user", ExpConfig()),
    ("ebpf_sk_cm_8_user",  ExpConfig()),
    ("enetstl_sk_cm_2_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_cm_4_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_cm_6_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_sk_cm_8_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("lkm_sk_cm_2_user", ExpConfig(), lambda: load_lkm("exp5/sk_cm_2.ko"), lambda: unload_lkm("sk_cm_2")),
    ("lkm_sk_cm_4_user", ExpConfig(), lambda: load_lkm("exp5/sk_cm_4.ko"), lambda: unload_lkm("sk_cm_4")),
    ("lkm_sk_cm_6_user",  ExpConfig(), lambda: load_lkm("exp5/sk_cm_6.ko"), lambda: unload_lkm("sk_cm_6")),
    ("lkm_sk_cm_8_user",  ExpConfig(), lambda: load_lkm("exp5/sk_cm_8.ko"), lambda: unload_lkm("sk_cm_8")),
    ("ebpf_carausel_tw_4_user",  ExpConfig()),
    ("ebpf_carausel_tw_8_user", ExpConfig()),
    ("ebpf_carausel_tw_16_user", ExpConfig()),
    ("ebpf_carausel_tw_32_user",  ExpConfig()),
    ("enetstl_carausel_tw_4_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_carausel_tw_8_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_carausel_tw_16_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_carausel_tw_32_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("lkm_carausel_tw_4_user",  ExpConfig(), lambda: load_lkm("exp6/carausel_tw_4.ko"), lambda: unload_lkm("carausel_tw_4")),
    ("lkm_carausel_tw_8_user",  ExpConfig(), lambda: load_lkm("exp6/carausel_tw_8.ko"), lambda: unload_lkm("carausel_tw_8")),
    ("lkm_carausel_tw_16_user",  ExpConfig(), lambda: load_lkm("exp6/carausel_tw_16.ko"), lambda: unload_lkm("carausel_tw_16")),
    ("lkm_carausel_tw_32_user",  ExpConfig(), lambda: load_lkm("exp6/carausel_tw_32.ko"), lambda: unload_lkm("carausel_tw_32")),
    ("ebpf_htss_25_user", ExpConfig()),
    ("ebpf_htss_50_user", ExpConfig()),
    ("ebpf_htss_75_user",  ExpConfig()),
    ("ebpf_htss_100_user",  ExpConfig()),
    ("enetstl_htss_25_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_htss_50_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_htss_75_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_htss_100_user",  ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("lkm_htss_25_user",  ExpConfig(), lambda: load_lkm("exp7/htss_25.ko"), lambda: unload_lkm("htss_25")),
    ("lkm_htss_50_user",  ExpConfig(), lambda: load_lkm("exp7/htss_50.ko"), lambda: unload_lkm("htss_50")),
    ("lkm_htss_75_user",  ExpConfig(), lambda: load_lkm("exp7/htss_75.ko"), lambda: unload_lkm("htss_75")),
    ("lkm_htss_100_user",  ExpConfig(), lambda: load_lkm("exp7/htss_100.ko"), lambda: unload_lkm("htss_100")),
    ("ebpf_cffs_1_user",  ExpConfig()),
    ("ebpf_cffs_2_user",  ExpConfig()),
    ("ebpf_cffs_3_user",  ExpConfig()),
    ("ebpf_cffs_4_user", ExpConfig()),
    ("enetstl_cffs_1_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cffs_2_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cffs_3_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("enetstl_cffs_4_user", ExpConfig(), lambda: load_lkm("eNetSTL/eNetSTL.ko"), lambda: unload_lkm("eNetSTL")),
    ("lkm_cffs_1_user", ExpConfig(), lambda: load_lkm("exp8/cFFS_1.ko"), lambda: unload_lkm("cFFS_1")),
    ("lkm_cffs_2_user", ExpConfig(), lambda: load_lkm("exp8/cFFS_2.ko"), lambda: unload_lkm("cFFS_2")),
    ("lkm_cffs_3_user", ExpConfig(), lambda: load_lkm("exp8/cFFS_3.ko"), lambda: unload_lkm("cFFS_3")),
    ("lkm_cffs_4_user", ExpConfig(), lambda: load_lkm("exp8/cFFS_4.ko"), lambda: unload_lkm("cFFS_4")),
    ("empty_base_user",  ExpConfig())
]

BIN_PATH = os.path.join(PROJECT_ROOT_DIR, "bin")
LKM_PATH = os.path.join(PROJECT_ROOT_DIR, "src/LKMs")

COUNT_MAP_OBJ_PATH = os.path.join(BPF_KERN_OBJ_DIR, 'count_pkt.o')
PACKET_COUNT_MAP_NAME = 'count_map'

if sys.stdout.isatty():
    COLOR_EMPHASIS = "\033[1;34m"
    COLOR_RESET = "\033[0m"
else:
    COLOR_EMPHASIS = ""
    COLOR_RESET = ""

pps_total_result = None
lat_no_total_result = None
lat_high_total_result = None

count_map = None   #bpf map 
class pkt_count(ct.Structure):
    _fields_  = [\
        ("rx_count", ct.c_uint64),\
        ("lat_count", ct.c_uint64),\
    ]

total_cpu = 1
METADATA_VALUE_TYPE = pkt_count

#for lat test, tmux client 
trex_client = None

def detach_xdp():
    commands = [
        f"ip -force link set dev {interface_name} xdpoffload off",
        f"ip -force link set dev {interface_name} xdpgeneric off",
        f"ip -force link set dev {interface_name} xdp off"
    ]
    try:
        for command in commands:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def attach_xdp(bpf_obj_name):
    command = f"{os.path.join(BIN_PATH, bpf_obj_name)}"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def load_lkm(module_path: str):
    if not os.path.isabs(module_path):
        module_path = os.path.join(LKM_PATH, module_path)
    try:
        subprocess.run(shlex.join(["insmod", module_path]), shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        raise  # re-raise the exception is necessary as it stops the execution

def unload_lkm(module_name: str):
    try:
        subprocess.run(shlex.join(["rmmod", module_name]), shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        raise

def __restart_flow(lat_pps, bg_pps, sleep_time=1, duration=5):
    trex_client.reset(ports=LAT_TEST_PORTS)
    profile = STLProfile.load(
            TRAFFIC_PRIFILE_FILE, direction=0, port_id=LAT_TEST_PORT, latency_pps=lat_pps, background_pps=bg_pps
        )
    trex_client.remove_all_streams(LAT_TEST_PORTS)
    trex_client.add_streams(profile.get_streams(), ports=LAT_TEST_PORTS)
    trex_client.start(ports=LAT_TEST_PORTS, mult="1", duration=duration)
    time.sleep(sleep_time)


def __eval_lat(lat_pps, bg_pps):
    try:
        result = None
        __restart_flow(lat_pps, bg_pps, sleep_time=3, duration=5)
        result = trex_client.get_pgid_stats(pgid_list=[])
        trex_client.wait_on_traffic(ports=LAT_TEST_PORTS)
    except STLError as e:
        print(
            format_text(
                "\nError while loading profile '{0}'\n".format(TRAFFIC_PRIFILE_FILE), "bold"
            )
        )
        print(e.brief() + "\n")
    except Exception as e:
        print("catch exception in eval lat")
        print(e)
    finally:
        return result

def __eval_progs_lat(lat_pps, bg_pps, test_prog, result_file, total_result_file, quiet):
    detach_xdp()
    # repeat the exp for multiple times
    for i in range(exp_repeat_count):
        attach_xdp(test_prog)
        time.sleep(1)
        if not quiet : print(f"Prog:[{prog}], Round:[{i}], Tensting latency with bg_pps: {bg_pps}pps, lat_pps: {lat_pps}pps")
        result = __eval_lat(lat_pps, bg_pps)
        detach_xdp()
        time.sleep(1)
        
        #10+port_id
        total_max = 0
        total_min = 0
        avg = 0
        
        if result != None: 
            try:
                #print(result)
                flow_lat = result.get("latency").get(int(10+LAT_TEST_PORT)).get("latency")
                avg  = flow_lat.get("average")
                total_min = flow_lat.get("total_min")
                total_max = flow_lat.get("total_max")
                histogram = flow_lat.get("histogram")
            except Exception as e:
                print("failed to get flow stats")
                print(e)
        else:
            print("latency result is None, something is wrong")
                
        if result_file is not None:
            if not quiet : 
                print("Avg: %f  total_max: %f total_min: %f"%(avg, total_max, total_min))
            result_file.write(f"{avg},{total_max},{total_min}\n")
        total_result_file.write(f"{test_prog},{avg},{total_max},{total_min},{str(histogram)}\n")


def print_non_load_lat(exp_config, test_prog, result_file, quiet=False):
    assert(isinstance(exp_config, ExpConfig))
    __eval_progs_lat(exp_config.lat_pps, exp_config.bg_no_pps, test_prog, result_file, lat_no_total_result, quiet)
        
def print_high_load_lat(exp_config, test_prog, result_file, quiet=False):
    assert(isinstance(exp_config, ExpConfig))
    __eval_progs_lat(exp_config.lat_pps, exp_config.bg_high_pps, test_prog, result_file, lat_high_total_result, quiet)

def print_rxcnt(count_map, wait_second, test_prog, result_file, quiet=False):
    if count_map == None: 
        print("err! pkt count is not init")
        return
    
    detach_xdp()
    
    __restart_flow("1000", str(int(30e6)), sleep_time=1, duration=-1)
    
    # repeat the exp for multiple times
    for i in range(exp_repeat_count):
        clear_map(count_map)

        attach_xdp(test_prog)
        time.sleep(1)

        prev_pkt_cnt = 0
        prev_total_latency = 0
        pps_array = []
        latency_array = []
        count = 0
        if not quiet : print(f"Prog:[{prog}], Round:[{i}], Reading pkt count")
        try:
            while count < wait_second or wait_second == -1:
                pkts = 0
                total_latency = 0
                for i in range(0, total_cpu):
                    current_cpu_value = count_map.lookup(ct.c_uint32(i))
                    # print(f"cpu:{i} rx_count: {current_cpu_value.rx_count}")
                    pkts += current_cpu_value.rx_count
                    total_latency += current_cpu_value.lat_count

                if pkts != 0:
                    delta_pkt_cnt = pkts - prev_pkt_cnt
                    delta_latency = total_latency - prev_total_latency
                    prev_total_latency = total_latency
                    prev_pkt_cnt = pkts
                    if delta_pkt_cnt > 0:
                        pps_array.append(delta_pkt_cnt)
                        delta_latency = delta_latency / delta_pkt_cnt
                        latency_array.append(delta_latency)
                        if not quiet : print("{}: {} pkt/s, {} ns".format(count, delta_pkt_cnt, delta_latency))
                count += 1
                time.sleep(1)
        finally:
            detach_xdp()
            time.sleep(1)
        if result_file is not None:
            if len(pps_array) == 0:
                print(f"[{prog}] haven't received any packet")
                avg_pkts = 0
                avg_latency = 0
            else:
                avg_pkts = round(np.average(pps_array[1:]), 2)
                avg_latency = round(np.average(latency_array[1:]), 2)
            if not quiet : print("Average pkts rate: %f"%avg_pkts)
            result_file.write(f"{avg_pkts},{avg_latency}\n")
        pps_total_result.write(f"{test_prog},{avg_pkts},{avg_latency}\n")

def clear_map(count_map):
    if count_map == None: 
        print("err! pkt count is not init")
        return
        # Fill the map with the random variables
    ini = count_map.value_type()
    ini.rx_count = 0
    ini.lat_count = 0
    for i in range(0, total_cpu):
        count_map.update(count_map.key_type(i), ini, 0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="sketch cm primitive")
    parser.add_argument('-c', '--count', type=int, default=-1, help = "count to print default is infinite")
    parser.add_argument('-i', '--include', help='pattern of programs to include')
    parser.add_argument('-e', '--exclude', help='pattern of programs to exclude')
    #positional argumentation
    parser.add_argument('cmds', type=str, nargs="+", help="eval, pps lat")
    args = parser.parse_args()
    cmds = []
    if 'all' in args.cmds: 
        cmds = ['pps', 'lat_no', 'lat_high']
    else:
        cmds = args.cmds
    
    if 'pps' in cmds:
        pps_total_result = open(os.path.join(PPS_LOG_PATH, "total_result.csv"), "w", buffering=1)
    
    if 'lat_no' in cmds :
        lat_no_total_result = open(os.path.join(LAT_NO_LOG_PATH, "total_result.csv"), "w", buffering=1)
        
    if 'lat_high' in cmds :
        lat_high_total_result = open(os.path.join(LAT_HIGH_LOG_PATH, "total_result.csv"), "w", buffering=1)
    
    final_count = args.count
    include_pattern = re.compile(args.include) if args.include else None
    exclude_pattern = re.compile(args.exclude) if args.exclude else None

    bpf_setup_obj = None
    
    if 'pps' in cmds: 
        with BPFObject(COUNT_MAP_OBJ_PATH) as bpf_obj:
            print("start load count map")
            bpf_obj.load()
            bpf_setup_obj = bpf_obj.transfer()
        count_map = BPFMap(bpf_setup_obj.get_map(PACKET_COUNT_MAP_NAME), ct.c_uint32, METADATA_VALUE_TYPE)


    trex_client = STLClient(verbose_level="error", server=TREX_SERVER)
    try:
        # connect to server
        trex_client.connect()
    except STLError as e:
        print(e)
        exit -1

    for i, entry in enumerate(bpf_prog_list):
        if len(entry) == 2:
            entry = (entry[0], entry[1], None, None)
        prog, config, setup, teardown = entry

        if include_pattern and not include_pattern.search(prog):
            continue
        if exclude_pattern and exclude_pattern.search(prog):
            continue

        print(f"{COLOR_EMPHASIS}Running {prog} ({i + 1}/{len(bpf_prog_list)}){COLOR_RESET}")
        try:
            if setup is not None:
                print(f'Running setup hook {setup}')
                try:
                    setup()
                except Exception as e:
                    print(f"Error in setup hook: {e}")
                    continue
            if 'pps' in cmds:
                with open(f"{os.path.join(PPS_LOG_PATH, f'{i + 1:03d}-{prog}')}.csv", "w", buffering=1) as pps_result_file:
                    print_rxcnt(count_map, final_count, prog, pps_result_file, quiet=PRINT_QUIET)
            if 'lat_no' in cmds:
                with open(f"{os.path.join(LAT_NO_LOG_PATH, f'{i + 1:03d}-{prog}')}.csv", "w", buffering=1) as lat_no_result_file:
                    print_non_load_lat(config, prog, lat_no_result_file, quiet=PRINT_QUIET)
            if 'lat_high' in cmds:
                with open(f"{os.path.join(LAT_HIGH_LOG_PATH, f'{i + 1:03d}-{prog}')}.csv", "w", buffering=1) as lat_high_result_file:
                    print_high_load_lat(config, prog, lat_high_result_file, quiet=PRINT_QUIET)
        except BaseException as e:
            if trex_client is not None:
                trex_client.remove_all_streams(ports=LAT_TEST_PORTS)
                trex_client.disconnect()
            print(e)
        finally:
            if teardown is not None:
                print(f'Running teardown hook {teardown}')
                try:
                    teardown()
                except Exception as e:
                    print(f"Error in teardown hook: {e}")

    if  count_map is not None:
        clear_map(count_map)
    if trex_client  is not None: 
        trex_client.disconnect()
    if pps_total_result is not None:
        pps_total_result.close()
    if lat_no_total_result is not None:
        lat_no_total_result.close()
    if lat_high_total_result is not None:
        lat_high_total_result.close()
    print("Done")
