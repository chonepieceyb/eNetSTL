#!/bin/zsh 


source $(cd "$(dirname "$0")"; pwd)"/"common.sh 
source ~/.zshrc

if [ $# -lt 1 ]
then 
    echo "usage: ./push_patch.sh patch_dir" 
    exit -1
fi 

PATCH_PATH=$PATCH_DIR$1

sftp_put -r /mnt/disk1/yangbin/CODING/WorkSpace/linux_deb/patches -l $PATCH_PATH seu_3 
