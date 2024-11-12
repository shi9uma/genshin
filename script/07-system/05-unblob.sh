#!/bin/sh

file_path=$1
file_name=$(basename $file_path)

work_dir=$(cd $(dirname $0); pwd)
input_dir="$work_dir/input"
output_dir="$work_dir/output"

check_dir() {
    if ! [ -d $1 ]; then
        mkdir -p $1
    fi
}

_rm() {
    if [ -f $1 ]; then
        rm $1
    fi
}

_rm $input_dir
_rm $output_dir

check_dir $work_dir
check_dir $input_dir
check_dir $output_dir

cp $file_path $input_dir
docker run \
  --rm \
  --pull always \
  -u $UID:$GID \
  -v $output_dir:/data/output \
  -v $input_dir:/data/input \
  ghcr.io/onekey-sec/unblob:latest "/data/input/$file_name"