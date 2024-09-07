#/usr/bin/env zsh

work_dir=$(dirname $0)
file_path=$work_dir/alist.yml
if [ ! -f $file_path ]; then
    curl \
        -x http://192.168.9.2:7890 \
        -fLo $file_path \
        https://raw.githubusercontent.com/shi9uma/genshin/main/app/02-alist/alist.yml
fi

mkdir -p $work_dir/data
mkdir -p $work_dir/storage/local $work_dir/storage/qbittorrent

sudo ln -s /mnt/