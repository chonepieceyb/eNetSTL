#!/bin/python3
from utils import * 
import argparse
from datetime import datetime
from common import *
import os
import coloredlogs

default_filters = ["bpf_pass_pkts", "dev_rx_pkts", "mac.rx_pkts"]

def get_latest_result(result_dir):
    results = os.listdir(result_dir)
    if len(results) == 0:
        return 
    resultdates = [datetime.strptime(date, RESULT_DATA_FORMAT) for date in results]
    resultdates = sorted(resultdates, reverse=True)
    return datetime.strftime(resultdates[0], RESULT_DATA_FORMAT)

def print_latest_exp(exp_dir, result_filter):
    _, exp_full_name = os.path.split(exp_dir)
    print("###EXP: %s###"%exp_full_name)
    modes = os.listdir(exp_dir)
    for m in modes:
        print("%s:"%m)
        latest_result = get_latest_result(os.path.join(exp_dir, m))
        show_stats_result(os.path.join(exp_dir, m, latest_result), result_filter)    
    print()


def get_exps(result_dir_prefix, exps):
    def __contain_all_files(mode_dir):
        if not os.path.isdir(mode_dir):
            return False
        results = os.listdir(mode_dir)
        for result in results:
            if not os.path.isfile(os.path.join(mode_dir, result)):
                return False 
        return True
    
    def __is_exp_dir(exp_dir):
        modes = os.listdir(exp_dir)
        for mode in modes:
            if not __contain_all_files(os.path.join(exp_dir, mode)):
                return False 
        return True 
    
    for exp in os.listdir(result_dir_prefix):
        exp_dir = os.path.join(result_dir_prefix, exp)
        if not os.path.isdir(exp_dir):
            continue 
        if __is_exp_dir(exp_dir):
            exps.append(os.path.join(result_dir_prefix, exp))
        else:
            #recursive
            get_exps(exp_dir, exps)

if __name__ == '__main__':
    coloredlogs.install(level='INFO')
    parser = argparse.ArgumentParser(description="show latest evaluation results")
    parser.add_argument('-f', '--show_filter', type=str, nargs="+", help="the filters to show in results")
    parser.add_argument('-p', '--result_dir_prefix', type=str, default = RESULTS_DIR, help="PATH-TO-RESULT-DIR")
    parser.add_argument('-r', '--exps', type=str, nargs="+", help="show PATH-TO-RESULT-DIR/<result_ouput>/ (if exp_name is not set show all results in PATH-TO-RESULT-DIR)") 
    args = parser.parse_args()
    
    filters = default_filters
    if args.show_filter != None: 
        filters = args.show_filters
    
    exps = []
    if args.exps == None: 
        #show all exp results
        get_exps(args.result_dir_prefix, exps)
    else:
        exps = [os.path.join(args.result_dir_prefix, exp) for exp in args.exps ]
    for exp in exps: 
        print_latest_exp(exp, filters)