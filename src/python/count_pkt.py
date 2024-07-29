#!/usr/bin/python
#
# univmon.py eBPF Countmin Sketch implementation
#
# Copyright (c) Sebastiano Miano <mianosebastiano@gmail.com>
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes
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
        ("rx_count", ct.c_uint32),\
    ]

METADATA_VALUE_TYPE = pkt_count * total_cpu

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
            all_cpu_values = count_map.lookup(ct.c_int(0))
            pkts = 0
            for per_cpu_value in all_cpu_values:
                pkts += per_cpu_value.rx_count

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

if __name__ == '__main__':  
    parser = argparse.ArgumentParser(description="sketch cm primitive")
    parser.add_argument('-i', '--interval', type=int, required=True, help = "interface to attach sketch")
    parser.add_argument('-c', '--count', type=int, default=-1, help = "count to print default is infinite")
    args = parser.parse_args()
    
    final_count = args.count
    
    with BPFObject(BPF_OBJ_PATH) as bpf_obj:
        print("start load")
        bpf_obj.load()
        count_map = BPFMap(bpf_obj.get_map(DROPCNT_MAP_NAME), ct.c_int, METADATA_VALUE_TYPE)
        # count_map.update(ct.c_int(0), 0, 0)
        try: 
            print_rxcnt(count_map, final_count) 
        except Exception as e:
            print(e)