#!/bin/bash 

source $(cd "$(dirname "$0")"; pwd)"/"common.sh 

cd $PROJECT_DIR$LINUX

git add .
git stash 
git stash drop 

#reset to v6.1
git reset --hard 830b3c68c1fb1e9176028d02ef86f3cf76aa2476
