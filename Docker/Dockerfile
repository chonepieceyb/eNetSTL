ARG KERNEL_VERSION

FROM ubuntu:22.04
LABEL author="chonepieceyb"

ARG KERNEL_VERSION

RUN apt update && apt install -y python3 vim git curl wget net-tools ethtool iproute2 iputils-ping gcc clang-15 llvm-15 clang-14 llvm-14 kmod bear meson cmake pkgconf libcap-dev libbfd-dev  build-essential libelf-dev libz-dev binutils-dev libcap-ng-dev m4 libpcap-dev pahole

COPY ./tmp/bpftool-libbpf-v7.3.0-sources /root/bpfdev/bpftool-libbpf-v7.3.0-sources

#compile
WORKDIR /root/bpfdev
RUN \
    make -C bpftool-libbpf-v7.3.0-sources/src clean && \
    make -C bpftool-libbpf-v7.3.0-sources/src -j "$(nproc)" && \
    make -C bpftool-libbpf-v7.3.0-sources/src install && \
    make -C bpftool-libbpf-v7.3.0-sources/libbpf/src install

ENV PKG_CONFIG_PATH "/usr/local/lib/pkgconfig/:/usr/lib/pkgconfig/:/usr/lib32/pkgconfig/:/usr/lib64/pkgconfig/"
ENV LD_LIBRARY_PATH "/usr/lib:/usr/local/lib:/usr/lib32:/usr/lib64"

#COPY kernel bpf tools and vmlinux

COPY ./vmlinux /lib/modules/${KERNEL_VERSION}/build/vmlinux
COPY ./tmp/tools /lib/modules/${KERNEL_VERSION}/build/tools

#config rust 

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rust_install.sh && \
    sh rust_install.sh -y  

RUN /root/.cargo/bin/rustup install 1.71.1 && \
    cd /lib/modules/${KERNEL_VERSION}/build && \
    /root/.cargo/bin/rustup override set 1.71.1-x86_64-unknown-linux-gnu && \
    /root/.cargo/bin/rustup component add rust-src

RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm