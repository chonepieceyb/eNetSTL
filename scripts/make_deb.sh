#!/bin/bash 

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

if [ $# -lt 1 ]
then 
    echo "usage: ./make_deb.sh patch_dir" 
    exit -1
fi 

#apply patch
$SCRIPT_DIR"apply_patch.sh" $1

#make deb 
cd $PROJECT_DIR$LINUX
make deb-pkg -j 40 LOCALVERSION=-$1 KDEB_PKGVERSION=$(make kernelversion)-1 >/dev/null 2>err_log

#recover patch 
$SCRIPT_DIR"recover_patch.sh" $1

#delete patch 
$SCRIPT_DIR"rm_patch.sh" $1
