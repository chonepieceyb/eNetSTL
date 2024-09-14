import os 

PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.dirname(PYTHON_DIR)
PROJECT_ROOT_DIR =  os.path.dirname(SRC_DIR)
LINUX_SRC_DIR = os.path.join(PROJECT_ROOT_DIR, "linux")
LIBBPF_SO_PATH = '/usr/lib64/libbpf.so'
BPF_KERN_OBJ_DIR = os.path.join(PROJECT_ROOT_DIR, 'install', 'bpf_kern_objs')
SCRITS_DIR=os.path.join(PROJECT_ROOT_DIR, "scripts")
XDP_CLEAR_SCRIPT_PATH=os.path.join(SCRITS_DIR, "detach_xdp.sh")
STAT_WATCH_PATH=os.path.join(SCRITS_DIR, "stat_watch_hw.py")
LOG_DIR = os.path.join(PROJECT_ROOT_DIR, "log")

#color 
RESULTS_DIR=os.path.join(PROJECT_ROOT_DIR, "results")
RESULT_DATA_FORMAT="%Y-%m-%d-%H-%M"

