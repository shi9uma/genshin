#/usr/bin/env zsh

work_dir=$(dirname $0)
if [ ! -f $work_dir/ddns-go.yml ]; then
    curl \
        -x http://192.168.9.2:7890 \
        -fLo $work_dir/ddns-go.yml \
        https://raw.githubusercontent.com/shi9uma/genshin/main/app/01-ddns-go/ddns-go.yml
fi