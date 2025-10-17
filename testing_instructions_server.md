## How to testing? 

### Step1: fix source files

fix errors according to ouput

### Step2: try to build 
1. run `./clean.sh -d -i bpfdev/linux6-16:latest` to clean previous building
2. run `./build.sh -d -i bpfdev/linux6-16:latest -DLOG_LEVEL=4 -DUSE_STATIC=OFF -DXDP_IF="ens2f0" -DXDP_MODE=XDP_FLAGS_DRV_MODE -DCMAKE_C_COMPILER="/usr/bin/clang"` (you should build with XDP_IF="veth")
3. check the output to find the excutable files path, typicaly it locates in project_root/bin
4. if building fails goto Step1: fix source files

### Step3: try to load bpf programs
1. use sudo run_bin.sh -d -i bpfdev/linux6-16:latest to run the generated exe
2. if tests failed, run `sudo cat /sys/kernel/debug/tracing/trace_pipe` (with a timeout of 10s is enough) to get eBPF programs log and fix issues in eBPF programs or user-space programs