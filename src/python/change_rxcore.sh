#!/bin/zsh
source /mnt/disk1/yangbin/CODING/WorkSpace/networking_project/scripts/exp/network_setting.sh

sudo ethtool -L ens2f0 rx 0 tx 0 combined $1

QUEUE_NUM=10

if [ $1 -gt 10 ]; then
    # 设置前十个队列和核心绑定
    for cpu in $(seq 0 9); do
        echo "set rx_queue ${cpu} to core ${cpu}"
        set_nic_rx_affinity ens2f0 $cpu $cpu
    done
    for cpu in $(seq 20 $((20+$1-10))); do
        echo "set rx_queue ${QUEUE_NUM} to core ${cpu}"
        set_nic_rx_affinity ens2f0 $QUEUE_NUM $cpu
        QUEUE_NUM=$((QUEUE_NUM+1))
    done
else
    for cpu in $(seq 0 $(($1-1))); do
        echo "set rx_queue ${cpu} to core ${cpu}"
        set_nic_rx_affinity ens2f0 $cpu $cpu
    done
fi