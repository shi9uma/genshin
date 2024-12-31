#!/bin/bash

#region
white='\033[0m'
green='\033[0;32m'
blue='\033[0;34m'
red='\033[31m'
yellow='\033[33m'
grey='\e[37m'
pink='\033[38;5;218m'
cyan='\033[96m'

# echo -e "${red}xxx${nc}"
nc='\033[0m'
#endregion

workdir=$(cd $(dirname $0); pwd)
genshin_dir_path=$(cd "$workdir/../../"; pwd)
encrypt_script_path="$genshin_dir_path/script/02-encryption/03-ez-encrypt.py"

mihomo_yaml_path="/d/software/mihomo-party/data/profiles/192281f8f10.yaml"
target_yaml_path="$workdir/magic.yaml"
salt_path="$workdir/salt"

if [ $# -eq 0 ]; then
    echo "usage: $0 {enc|dec|show}"
    exit 1
fi

case "$1" in
    enc)
        python $encrypt_script_path \
            -i $mihomo_yaml_path \
            -o $target_yaml_path \
            -s $salt_path \
            enc
        ;;
    dec)
        python $encrypt_script_path \
            -i $target_yaml_path \
            -o $mihomo_yaml_path \
            -s $salt_path \
            dec
        ;;
    show)
        echo -e "encrypt_script_path: ${green}${encrypt_script_path}${nc}"
        echo -e "mihomo_yaml_path: ${green}${mihomo_yaml_path}${nc}"
        echo -e "target_yaml_path: ${green}${target_yaml_path}${nc}"
        echo -e "salt_path: ${green}${salt_path}${nc}"
        ;;
    *)
        echo "usage: $0 {enc|dec|show}"
esac