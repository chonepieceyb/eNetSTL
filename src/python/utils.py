from common import *
import logging 
import time
import os
class ArgWrapper:
    def __init__(self, arg_parse_func, *, use_res_args = False):
        self.arg_parse_func = arg_parse_func
        self.use_res_args = use_res_args

    def __call__(self, func):
        def new_func(*args, **kw):
            kw_args = {}
            if "arg_list" in kw:
                if self.use_res_args: 
                    kw_args, res_args = self.arg_parse_func(kw.pop("arg_list"))
                    if res_args == None: 
                        res_args = []
                    kw_args["res_args"] = res_args
                else:
                    kw_args = self.arg_parse_func(kw.pop("arg_list"))
            else:
                kw_args = kw 
            return func(*args, **kw_args)
        return new_func 

def run_cmd(cmd, *, quit_on_fail=False):
    res = os.waitstatus_to_exitcode(os.system(cmd))
    if quit_on_fail and res != 0:
        exit(res)
    return res

def _read_cpu_range(path):
    cpus = []
    with open(path, 'r') as f:
        cpus_range_str = f.read()
        for cpu_range in cpus_range_str.split(','):
            rangeop = cpu_range.find('-')
            if rangeop == -1:
                cpus.append(int(cpu_range))
            else:
                start = int(cpu_range[:rangeop])
                end = int(cpu_range[rangeop+1:])
                cpus.extend(range(start, end+1))
    return cpus

def get_online_cpus():
    return _read_cpu_range('/sys/devices/system/cpu/online')

def get_possible_cpus():
    return _read_cpu_range('/sys/devices/system/cpu/possible')

default_stats_filters = ["bpf_pass_pkts", "bpf_app1_pkts", "bpf_app2_pkts", "bpf_app3_pkts", "rvec_0_rx_pkts", "rx_dropped", "rx_errors", "dev_rx_pkts", "dev_rx_discards", "dev_rx_errors", "mac.rx_pkts", "mac.rx_errors"]
def stats_watching(devname, result_file, watching_time = 6, filters = []):
    '''
    @devname: interface to watch
    @watching_time: the time to watching
    '''
    assert watching_time >= 1 and "watching time must >=1s"
    filter_flags = " ".join(["-f %s"%filter for filter in filters])
    session_name = "%s_stats_watching"%devname
    stats_watching_cmd = "tmux new-session -d -s %s '%s -n %d -c %s %s > \"%s\"'"%(session_name, STAT_WATCH_PATH, watching_time, devname, filter_flags, result_file)
    run_cmd("tmux kill-session -t %s > /dev/null 2>&1"%(session_name))
    try:
        if run_cmd(stats_watching_cmd) == 0:
            logging.debug("start stats watching: %s", stats_watching_cmd)
        else:
            raise RuntimeError("failed to start stats watching, cmds %s, "%stats_watching_cmd)
        while True:
            if run_cmd("tmux has-session -t %s > /dev/null 2>&1"%session_name) != 0:
                break 
            time.sleep(1)
    except Exception as e: 
        run_cmd("tmux kill-session -t %s > /dev/null 2>&1"%(session_name))
        raise

def show_stats_result(result_file, filters = default_stats_filters):
    __awkcmd = "cat %s | \
        awk '/%s /{print $2}' | \
        sed 's/,//g' | \
        awk 'BEGIN{count = 0; all = 0; last=0} NR>=2{count+=1; all+=$1; last=$1} END{count-=1; all-=last; if (count != 0) {print \"%s:\" int(all/count);} else {print \"awk_error\"; exit 1}}'"
    for filter in filters:
        awkcmd = __awkcmd%(result_file, filter, filter)
        logging.debug("stats parsing cmd: %s"%awkcmd)
        if (run_cmd(awkcmd) != 0):
            raise RuntimeError("failed to parse stats result")

total_cpu = len(get_possible_cpus())

ip_str_to_int = lambda x: sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])


def sscanf(format, input, sep = ':'):
    dfuncs = {
        "%d" : int,
        "%f" : float,
        "%s" : str
    }
    input_dfunc = [dfuncs[s] for s in format.split(sep)]
    return tuple([dfunc(s) for dfunc, s in zip(input_dfunc, input.split(sep))])