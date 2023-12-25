#!/bin/bash 
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color
cpu=$(cat /proc/cpuinfo | grep processor | wc -l)

LIBBPF_TAG=v1.3.0
BCC_TAG=v0.28.0

set -e

git submodule init 
git submodule update 

#install and compile libbpf
if [ -d "./linux" ]; then
    echo -e "${COLOR_GREEN} [INFO] using libbpf from ./linux source code${COLOR_OFF}"
    echo -e "${COLOR_GREEN} [INFO] builing ./linux/tools/lib/bpf (libbpf)${COLOR_OFF}"
    pushd "./linux/tools/lib/bpf" > /dev/null
    make clean
    rm -rf ./compile_commands.json 
    bear -- make -j $cpu 
    echo -e "${COLOR_GREEN} [INFO] builing ./linux/tools/bpf (bpftool)${COLOR_OFF}"
    cd ../bpf
    make clean 
    rm -rf ./compile_commands.json 
    bear -- make -j $cpu 
    popd > /dev/null
else
    echo -e "${COLOR_GREEN} [INFO] using libbpf $LIBBPF_TAG from https://github.com/libbpf/libbpf.git${COLOR_OFF}"
    echo -e "${COLOR_GREEN} [INFO] using bpftool $LIBBPF_TAG from https://github.com/libbpf/bpftool.git${COLOR_OFF}"
    echo -e "${COLOR_GREEN} [INFO] you may also using libbpf from linux source tree by create soft link of linux source code in ./linux${COLOR_OFF}"
    echo -e "${COLOR_GREEN} [INFO] builing ./deps/libbpf/${COLOR_OFF}"
    pushd "./deps/libbpf/" > /dev/null
    git checkout master 
    git clean -fd
    git checkout $LIBBPF_TAG > /dev/null
    cd ./src
    make clean
    rm -rf ./compile_commands.json 

    __http_proxy=$http_proxy
    __https_proxy=$https_proxy
    __all_proxy=$all_proxy
    unset http_proxy
    unset https_proxy
    unset all_proxy
    bear -- make -j $cpu
    export http_proxy=$__http_proxy
    export https_proxy=$__https_proxy
    export all_proxy=$__all_proxy
    sudo make install 
    
    popd > /dev/null
    # set +e
    # dpkg --list | grep linux-tools-$(uname -r)
    # if (( $? != 0 )); then 
    #     echo -e "${COLOR_GREEN} [INFO] try to install linux-tools-$(uname -r)${COLOR_OFF}"
    #     set -e
    #     sudo apt-get install linux-tools-$(uname -r)
    # else 
    #     echo -e "${COLOR_GREEN} [INFO] found linux-tools-$(uname -r)${COLOR_OFF}"
    #     set -e 
    # fi     
    pushd "./deps/bpftool" > /dev/null
    git submodule update --init 
    cd src
    make -j $cpu 
    popd > /dev/null
fi 
echo -e "${COLOR_GREEN} [INFO] installing libbpf bpftool finish ${COLOR_OFF}"

#install bcc
echo -e "${COLOR_GREEN} [INFO] installing bcc $BCC_TAG. .. ${COLOR_OFF}"
pushd "./deps/bcc/" > /dev/null
git checkout master 
git clean -fd
git checkout $BCC_TAG
#install LLVM dependencies 
sudo apt-get install -y libllvm14 llvm-14-dev libclang-14-dev
export LLVM_ROOT="/usr/lib/llvm-14"
rm -rf build
mkdir build && cd build
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ../
make -j $cpu 
sudo make install
cmake -DPYTHON_CMD=python3 ..
pushd src/python/ > /dev/null
make
#remove the old bcc python 
sudo rm -rf /usr/lib/python3/dist-packages/bcc
sudo make install
popd > /dev/null
popd  > /dev/null
echo -e "${COLOR_GREEN} [INFO] installing bcc finish ${COLOR_OFF}"

echo -e "${COLOR_GREEN} [INFO] generate vmlinux.h${COLOR_OFF}"

./scripts/gen_vmlinux_h.sh

echo -e "${COLOR_GREEN} [INFO] building demo${COLOR_OFF}" 

rm -rf ./build
rm -rf ./install

cmake -B build ./
pushd build > /dev/null
make
pushd > /dev/null

echo -e "${COLOR_GREEN} [INFO] bpf objects install in ./install${COLOR_OFF}"
echo -e "${COLOR_GREEN} [INFO] demo bin install in ./bin${COLOR_OFF}" 