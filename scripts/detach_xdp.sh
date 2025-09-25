#!/bin/bash

function detach_xdp_hw() {
    sudo ip -force link set dev $1 xdpoffload off
}

function detach_xdp_skb() {
    sudo ip -force link set dev $1 xdpgeneric off
}

function detach_xdp_drv() {
    sudo ip -force link set dev $1 xdp off
}

function echo_help() {
    echo "usage $0 nic (skb|hw|all)" 
    exit -1
}

if (( $# != 2 )); then
    echo_help
fi 

if [[ $2 == "skb" ]]; then 
    detach_xdp_skb $1
elif [[ $2 == "hw" ]]; then    
    detach_xdp_hw $1
elif [[ $2 == "drv" ]]; then  
    detach_xdp_drv $1
elif [[ $2 == "all" ]]; then
    detach_xdp_skb $1
    detach_xdp_hw $1
    detach_xdp_drv $1
else
    echo_help
fi