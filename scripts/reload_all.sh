#!/bin/bash
# 使用方法：调用该脚本需传入数字参数i，对应加载运行PROG数组中的第i个程序
source $(cd "$(dirname "$0")"; pwd)"/"common.sh
EXTERN_KERN_MODULES="extern_kern_modules/"
# 写要加载的模块和程序
MODULE=("sketch_lib" "bpf_custom_map_demo")
PROG=("sketch_primitive_demo_user" "sketch_heap_demo_user")
LINK=("sketch_primitive_link" "sketch_heap_link")
# 重新编译并加载extern_kern_modules/下的内核模块
echo "Start recompile modules and load them."
for i in "${!MODULE[@]}"
do
    cd $PROJECT_DIR$EXTERN_KERN_MODULES${MODULE[i]} && make clean && make
    IS_LOADED=$(sudo lsmod | grep ${MODULE[i]})
    if [ ! -z "$IS_LOADED" ]; then
        sudo rmmod ${MODULE[i]}
    fi
    sudo insmod $PROJECT_DIR$EXTERN_KERN_MODULES${MODULE[i]}"/"${MODULE[i]}".ko"
    echo "Module: ""${MODULE[i]}"" loaded!"
done


echo "Start build samples."
cmake --build $SAMPLES_DIR"build"
make install -C $SAMPLES_DIR"build"
sudo dmesg -C
sudo trace-cmd clear

for i in "${!LINK[@]}"
do
    # if [ ! -z "$(sudo ls /sys/fs/bpf/${LINK[i]})" ]; then
        sudo rm /sys/fs/bpf/${LINK[i]}
    # fi
done

cd $SAMPLES_DIR"bin/"

# 根据参数1，2执行指定的bpf程序
echo "Run Prog: "${PROG[$1]}
sudo "./"${PROG[$1]}
sleep 5
echo "Start output."
sudo cat /tracing/trace_pipe > $PROJECT_DIR"trace_pipe_output.txt" &
sudo dmesg > $PROJECT_DIR"kernel_output.txt"

for i in "${!LINK[@]}"
do
    sudo rm /sys/fs/bpf/${LINK[i]}
done

echo "End output."