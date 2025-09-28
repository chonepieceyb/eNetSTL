## How to testing? 

### Step1: fix source files

fix errors according to ouput

### Step2: try to build 
1. run `./clean.sh -d` to clean previous building
2. run `./build.sh -d -DLOG_LEVEL=4 -DUSE_STATIC=ON -DXDP_IF="eth1" -DXDP_MODE=XDP_FLAGS_SKB_MODE` (you should build with XDP_IF="veth")
3. check the output to find the excutable files path, typicaly it locates in project_root/bin
4. if building fails goto Step1: fix source files

### Step3: connect remote server
1. check if you have start remote server first, if not run `scripts/new_kernel_dbg_session.sh` to start a remote server
2. check the ouput file to get how to connect remote server using ssh
3. the ssh user is `seu` password is `123456` 
  * if you can not login to remote server, restart this step and directly run `scripts/new_kernel_dbg_session.sh` to start a new one server. else goto Step4 
4. an example ssh commands: `sshpass -p "123456" ssh -o StrictHostKeyChecking=no -p 3333 seu@127.0.0.1` IMPORTANT: use -p 3333 rather than -P 3333

### Step4: run the test
1. copy the excutable files for testing to remote server
2. run `sudo cat /sys/kernel/debug/tracing/trace_pipe` (timeout 1s is enough) for a shot time to clear the trace pipe. 
   * if you got `cat: /sys/kernel/debug/tracing/trace_pipe: Device or resource busy` , find which process holds trace_pipe, directly kill it, and retry.
3. directly run it , for example `sudo ./execfile` 
4. check if the eBPF programs are loaded successfully, if not fix loading issue first
 * you can check `project_dir/linux/testing/lib/bpf/libbpf.h` to check libbpf API and  `project_dir/linux/testing/lib/bpf/libbpf.c` for implementation
5. if eBPF programs have loaded successfully, check if all test passes 
6. if tests failed, run `sudo cat /sys/kernel/debug/tracing/trace_pipe` (with a timeout of 10s is enough) to get eBPF programs log and fix issues in eBPF programs or user-space programs
    * if you got `cat: /sys/kernel/debug/tracing/trace_pipe: Device or resource busy` , find which process holds trace_pipe, directly kill it, and retry.
    * if you got nothing, it means that eBPF programs do not run at all or eBPF programs log nothing
7. for anly failure, goto  Step1: fix source files
8. if run bash timeout, it likely the ssh issue, goto step3 and restart a new remote server using `scripts/new_kernel_dbg_session.sh` and clear ~/.ssh/known_hosts accrodingly
