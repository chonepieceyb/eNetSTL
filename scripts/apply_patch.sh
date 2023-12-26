#!/bin/bash 

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

if [ $# -lt 1 ]
then 
    echo "usage: ./apply_patch.sh patch_dir" 
    exit -1
fi 

PATCH_PATH=$PATCH_DIR$1/

patches=$(ls $PATCH_PATH)

cd $PROJECT_DIR$LINUX

set -e

if (( $# == 2 ))
then
    pushd $PATCH_PATH > /dev/null 
    p=$(ls | grep -e "^${2}")
    echo $PATCH_PATH$p
else
    for p in $patches
    do
        echo $PATCH_PATH$p
        patch -p1 < $PATCH_PATH$p
    done
fi