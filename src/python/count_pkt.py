#!/usr/bin/python
#
# univmon.py eBPF Countmin Sketch implementation
#
# Copyright (c) Sebastiano Miano <mianosebastiano@gmail.com>
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import sys
sys.path.append("..") 
from libbpf import *
from common import *
import time 
import numpy as np 
from bpftools import *
from socket import if_nametoindex
import argparse
from utils import *

BPF_OBJ_PATH = os.path.join(BPF_KERN_OBJ_DIR, 'count_pkt.o')
DROPCNT_MAP_NAME = 'count_map'
count_map = None   #bpf map 

class pkt_count(ct.Structure):
    _fields_  = [\
        ("rx_count", ct.c_uint64),\
    ]

total_cpu = 40
METADATA_VALUE_TYPE = pkt_count

def print_rxcnt(count_map, final_count, quiet=False, print_pkts=True, print_bytes=False):
    if count_map == None: 
        print("err! pkt count is not init")
        return

    prev_pkt_cnt = 0
    pps_array = []
    count = 0
    if not quiet : print("Reading pkt count")
    try:
        while count < final_count or final_count == -1:
            pkts = 0
            for i in range(0, total_cpu):
                current_cpu_value = count_map.lookup(ct.c_uint32(i))
                print(f"cpu:{i} rx_count: {current_cpu_value.rx_count}")
                pkts += current_cpu_value.rx_count

            if pkts and print_pkts:
                delta = pkts - prev_pkt_cnt
                prev_pkt_cnt = pkts
                if delta > 0:
                    pps_array.append(delta)
                    if not quiet : print("{}: {} pkt/s".format(count, delta))
            count += 1
            time.sleep(1)
    except KeyboardInterrupt:
        pass 
        
    avg = list()

    if print_pkts:
        avg_pkts = round(np.average(pps_array[1:]), 2)
        avg.append(avg_pkts)
        print("Average pkts rate: %f"%avg_pkts)
        
    return avg

def clear_map(count_map):
    if count_map == None: 
        print("err! pkt count is not init")
        return
        # Fill the map with the random variables
    ini = count_map.value_type()
    ini.rx_count = 0
    for i in range(0, total_cpu):
        count_map.update(count_map.key_type(i), ini, 0)

if __name__ == '__main__':  
    parser = argparse.ArgumentParser(description="sketch cm primitive")
    parser.add_argument('-i', '--interval', type=int, required=True, help = "interface to attach sketch")
    parser.add_argument('-c', '--count', type=int, default=-1, help = "count to print default is infinite")
    args = parser.parse_args()
    
    final_count = args.count
    
    with BPFObject(BPF_OBJ_PATH) as bpf_obj:
        print("start load")
        bpf_obj.load()
        count_map = BPFMap(bpf_obj.get_map(DROPCNT_MAP_NAME), ct.c_uint32, METADATA_VALUE_TYPE)
        clear_map(count_map)
        time.sleep(1)
        # count_map.update(ct.c_int(0), 0, 0)
        try: 
            print_rxcnt(count_map, final_count) 
        except Exception as e:
            print(e)