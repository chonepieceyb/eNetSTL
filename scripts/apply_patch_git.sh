#!/bin/bash 

# ./apply_patch.sh patch_dir

function echo_help() {
    echo "resolve git am confilics: "
    echo "git apply --reject <path_dir>"
    echo "git status (check .rej)"
    echo "solve conflicts manually"
    echo "git add"
    echo "git am --resolved"
}

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 
if [ $# -lt 1 ]
then 
    echo "usage: ./apply_patch_git.sh patch_dir" 
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
    popd > /dev/null 
    echo $PATCH_PATH$p
    git am $PATCH_PATH$p
else
    for p in $patches
    do
        echo $PATCH_PATH$p
        git am $PATCH_PATH$p
    done
fi