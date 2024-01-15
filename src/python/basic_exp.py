#!/bin/python3
from utils import * 
import argparse
from datetime import datetime
from common import *
import os
import coloredlogs

default_filters = ["bpf_pass_pkts", "dev_rx_pkts", "mac.rx_pkts"]
RESULT_DATA_FORMAT="%Y-%m-%d-%H-%M"

if __name__ == '__main__':
    coloredlogs.install(level='INFO')
    parser = argparse.ArgumentParser(description="basic pps evaluation scripts")
    parser.add_argument('-f', '--show_filter', type=str, nargs="+", help="the filters to show in results")
    parser.add_argument('-p', '--result_dir_prefix', type=str, default = RESULTS_DIR, help="PATH-TO-RESULT-DIR")
    parser.add_argument('-r', '--exp_name', type=str, required=True, help="PATH-TO-RESULT-DIR/<result_ouput>/") 
    parser.add_argument('-m', '--mode', type=str, required=True, help="PATH-TO-RESULT-DIR/<result_output>/mode/result/") 
    parser.add_argument('-d', '--dev', type=str, required=True, help="interface to watch") 
    args = parser.parse_args()
    
    filters = default_filters
    if args.show_filter != None: 
        filters = args.show_filters
    
    exp_dir= os.path.join(args.result_dir_prefix, args.exp_name)
    if not os.path.exists(exp_dir):
        os.makedirs(exp_dir, exist_ok=True)
    exp_dir_mode =  os.path.join(exp_dir, args.mode)
    if not os.path.exists(exp_dir_mode):
        os.makedirs(exp_dir_mode, exist_ok=True)
            
    time_str = datetime.now().strftime(RESULT_DATA_FORMAT)
    result_file =  os.path.join(exp_dir_mode, time_str)
     
    run_cmd("touch %s && chmod 666 %s"%(result_file, result_file), quit_on_fail=True)
    
    stats_watching(args.dev, result_file, 7, filters=[])
    logging.info("Exp %s %s results: "%(args.exp_name, args.mode))
    show_stats_result(result_file, filters=filters)
