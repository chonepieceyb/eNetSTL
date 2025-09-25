#!/bin/bash 

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

if [ $# -lt 1 ]
then 
    echo "usage: ./recover_patch.sh patch_dir" 
    exit -1
fi 

PATCH_PATH=$PATCH_DIR$1/

patches=$(ls $PATCH_PATH)

cd $PROJECT_DIR$LINUX

for p in $patches
do
    patch -p1 -R < $PATCH_PATH$p
done
