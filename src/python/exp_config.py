import os
from common import *

interface_name = "ens2f0"

exp_repeat_count = 5

PPS_LOG_PATH = os.path.join(PROJECT_ROOT_DIR, "log", "pps")
if not os.path.exists(PPS_LOG_PATH):
    os.makedirs(PPS_LOG_PATH)

LAT_NO_LOG_PATH = os.path.join(PROJECT_ROOT_DIR, "log", "latency_no_load")
if not os.path.exists(LAT_NO_LOG_PATH):
    os.makedirs(LAT_NO_LOG_PATH)
    
LAT_HIGH_LOG_PATH = os.path.join(PROJECT_ROOT_DIR, "log", "latency_high_load")
if not os.path.exists(LAT_HIGH_LOG_PATH):
    os.makedirs(LAT_HIGH_LOG_PATH)    

TREX_SERVER="223.3.71.41"
TRAFFIC_PRIFILE_FILE=os.path.join(os.path.dirname(__file__), "stream_generator.py")
LAT_TEST_PORT = 0
LAT_TEST_PORTS = [LAT_TEST_PORT]
PRINT_QUIET=False