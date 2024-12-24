#!/bin/sh

#region
white='\033[0m'
green='\033[0;32m'
blue='\033[0;34m'
red='\033[31m'
yellow='\033[33m'
grey='\e[37m'
pink='\033[38;5;218m'
cyan='\033[96m'
#endregion

update() {
    apt-get update -y
    apt-get upgrade -y
}

check() {
    exit 0
}

while getopts "uc3h" opt; do
	case ${opt} in
		u )
		info "update"
			update &> /dev/null

			if [ $? -eq 0 ]; then
				auto_update_success=1
			else
				auto_update_success=0
			fi

			if [ $auto_update_success -eq 1 ]; then
				info "update success"
			else
				fail "update failed"
			fi
			;;
		b )
        info "check"
			seperator
			info "check num: 1 - 10"
			read check_num
			while true
			do
				if ! [[ "$check_num" =~ ^[0-9]+$ ]]; then
					fail "input check_num"
					read check_num_result
				else
					break
				fi
			done

			read check_num_result
			while true
			do
				if ! [[ "$check_num_result" =~ ^[0-9]+$ ]] || [ $check_num_result -lt 1 ] || [ $check_num_result -gt 31 ] ; then
					read result
				else
					break
				fi
			done

            echo "check_num: $check_num"
            echo "check_num_result: $check_num_result"
            ;;
		3 )
		info "test"
            exit 0
			;;
		h )
			info "Usage: $0 [-u] [-b] [-3] [-h]"
			info "opt: "
            info "  -u: update"
            info "  -b: check"
            info "  -3: exit"
			exit 0
			;;
		\? )
			info "Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
	esac
done