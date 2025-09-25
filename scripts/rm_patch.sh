#!/bin/bash

source $(cd "$(dirname "$0")"; pwd)"/"common.sh

if [ $# -lt 1 ]
then
    echo "usage: ./rm_patch.sh patch_dir"
    exit -1
fi

PATCH_PATH=$PATCH_DIR$1

rm -rf $PATCH_PATH


