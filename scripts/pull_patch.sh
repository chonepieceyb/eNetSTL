#!/bin/zsh 

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 
source ~/.zshrc

if [ $# -lt 1 ]
then 
    echo "usage: ./pull_patch.sh patch_dir" 
    exit -1
fi 

sftp_get -r /mnt/disk1/yangbin/CODING/WorkSpace/linux_testbed/patches/$1 -l $PATCH_DIR seu_3 
