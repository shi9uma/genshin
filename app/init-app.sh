#!/usr/bin/env zsh

create_dir() {
    if [ ! -d $1 ]; then
        mkdir -p $1
    fi
}

app=(ddns-go alist qbittorrent synctv transfersh hedgedoc outline reference cyberchef gtfobins explainshell hastebin)
url_base=https://raw.githubusercontent.com/shi9uma/genshin/main/app
work_dir=$(dirname $0)

for index in {01..12}; do
    app_name=${app[$index]}
    echo $app_name
done

for index in {01..12}; do
    app_name=${app[$index]}

    app_dir=$work_dir/$index-$app_name
    init_file_name="init-$app_name.sh"
    init_file_path=$app_dir/$init_file_name
    url=$url_base/$index-$app_name/$init_file_name

    create_dir $app_dir
    curl -fLo $init_file_path $url
    chmod +x $init_file_path
    eval $init_file_path
done