# ~/.zshrc file for zsh interactive shells.
# see /usr/share/doc/zsh/examples/zshrc for examples

setopt autocd              # change directory just by typing its name
#setopt correct            # auto correct mistakes
setopt interactivecomments # allow comments in interactive mode
setopt magicequalsubst     # enable filename expansion for arguments of the form ‘anything=expression’
setopt nonomatch           # hide error message if there is no match for the pattern
setopt notify              # report the status of background jobs immediately
setopt numericglobsort     # sort filenames numerically when it makes sense
setopt promptsubst         # enable command substitution in prompt

WORDCHARS=${WORDCHARS//\/} # Don't consider certain characters part of the word

# hide EOL sign ('%')
PROMPT_EOL_MARK=""

# configure key keybindings
bindkey -e                                        # emacs key bindings
bindkey ' ' magic-space                           # do history expansion on space
bindkey '^U' backward-kill-line                   # ctrl + U
bindkey '^[[3;5~' kill-word                       # ctrl + Supr
bindkey '^[[3~' delete-char                       # delete
bindkey '^[[1;5C' forward-word                    # ctrl + ->
bindkey '^[[1;5D' backward-word                   # ctrl + <-
bindkey '^[[5~' beginning-of-buffer-or-history    # page up
bindkey '^[[6~' end-of-buffer-or-history          # page down
bindkey '^[[H' beginning-of-line                  # home
bindkey '^[[F' end-of-line                        # end
bindkey '^[[Z' undo                               # shift + tab undo last action

# enable completion features
autoload -Uz compinit
compinit -d ~/.cache/zcompdump
zstyle ':completion:*:*:*:*:*' menu select
zstyle ':completion:*' auto-description 'specify: %d'
zstyle ':completion:*' completer _expand _complete
zstyle ':completion:*' format 'Completing %d'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' list-colors ''
zstyle ':completion:*' list-prompt %SAt %p: Hit TAB for more, or the character to insert%s
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
zstyle ':completion:*' rehash true
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd'

# History configurations
HISTFILE=~/.zsh_history
HISTSIZE=1000
SAVEHIST=2000
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
setopt hist_verify            # show command with history expansion to user before running it
#setopt share_history         # share command history data

# force zsh to show the complete history
# alias history="history 0"

# configure `time` format
TIMEFMT=$'\nreal\t%E\nuser\t%U\nsys\t%S\ncpu\t%P'

# make less more friendly for non-text input files, see lesspipe(1)
#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        # We have color support; assume it's compliant with Ecma-48
        # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
        # a case would tend to support setf rather than setaf.)
        color_prompt=yes
    else
        color_prompt=
    fi
fi

configure_prompt() {
    prompt_symbol=\(Ծ‸Ծ\)
    # Skull emoji for root terminal
    #[ "$EUID" -eq 0 ] && prompt_symbol=💀
    case "$PROMPT_ALTERNATIVE" in
        twoline)
            PROMPT=$'%F{%(#.blue.green)}┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n'$prompt_symbol$'%m%b%F{%(#.blue.green)})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]\n└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
            # Right-side prompt with exit codes and background processes
            #RPROMPT=$'%(?.. %? %F{red}%B⨯%b%F{reset})%(1j. %j %F{yellow}%B⚙%b%F{reset}.)'
            ;;
        oneline)
            PROMPT=$'${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%B%F{%(#.red.blue)}%n@%m%b%F{reset}:%B%F{%(#.blue.green)}%~%b%F{reset}%(#.#.$) '
            RPROMPT=
            ;;
        backtrack)
            PROMPT=$'${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%B%F{red}%n@%m%b%F{reset}:%B%F{blue}%~%b%F{reset}%(#.#.$) '
            RPROMPT=
            ;;
    esac
    unset prompt_symbol
}

# The following block is surrounded by two delimiters.
# These delimiters must not be modified. Thanks.
# START KALI CONFIG VARIABLES
PROMPT_ALTERNATIVE=twoline
NEWLINE_BEFORE_PROMPT=yes
# STOP KALI CONFIG VARIABLES

if [ "$color_prompt" = yes ]; then
    # override default virtualenv indicator in prompt
    VIRTUAL_ENV_DISABLE_PROMPT=1

    configure_prompt

    # enable syntax-highlighting
    if [ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]; then
        . /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
        ZSH_HIGHLIGHT_HIGHLIGHTERS=(main brackets pattern)
        ZSH_HIGHLIGHT_STYLES[default]=none
        ZSH_HIGHLIGHT_STYLES[unknown-token]=underline
        ZSH_HIGHLIGHT_STYLES[reserved-word]=fg=cyan,bold
        ZSH_HIGHLIGHT_STYLES[suffix-alias]=fg=green,underline
        ZSH_HIGHLIGHT_STYLES[global-alias]=fg=green,bold
        ZSH_HIGHLIGHT_STYLES[precommand]=fg=green,underline
        ZSH_HIGHLIGHT_STYLES[commandseparator]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[autodirectory]=fg=green,underline
        ZSH_HIGHLIGHT_STYLES[path]=bold
        ZSH_HIGHLIGHT_STYLES[path_pathseparator]=
        ZSH_HIGHLIGHT_STYLES[path_prefix_pathseparator]=
        ZSH_HIGHLIGHT_STYLES[globbing]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[history-expansion]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[command-substitution]=none
        ZSH_HIGHLIGHT_STYLES[command-substitution-delimiter]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[process-substitution]=none
        ZSH_HIGHLIGHT_STYLES[process-substitution-delimiter]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[single-hyphen-option]=fg=green
        ZSH_HIGHLIGHT_STYLES[double-hyphen-option]=fg=green
        ZSH_HIGHLIGHT_STYLES[back-quoted-argument]=none
        ZSH_HIGHLIGHT_STYLES[back-quoted-argument-delimiter]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[single-quoted-argument]=fg=yellow
        ZSH_HIGHLIGHT_STYLES[double-quoted-argument]=fg=yellow
        ZSH_HIGHLIGHT_STYLES[dollar-quoted-argument]=fg=yellow
        ZSH_HIGHLIGHT_STYLES[rc-quote]=fg=magenta
        ZSH_HIGHLIGHT_STYLES[dollar-double-quoted-argument]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[back-double-quoted-argument]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[back-dollar-quoted-argument]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[assign]=none
        ZSH_HIGHLIGHT_STYLES[redirection]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[comment]=fg=black,bold
        ZSH_HIGHLIGHT_STYLES[named-fd]=none
        ZSH_HIGHLIGHT_STYLES[numeric-fd]=none
        ZSH_HIGHLIGHT_STYLES[arg0]=fg=cyan
        ZSH_HIGHLIGHT_STYLES[bracket-error]=fg=red,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-1]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-2]=fg=green,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-3]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-4]=fg=yellow,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-5]=fg=cyan,bold
        ZSH_HIGHLIGHT_STYLES[cursor-matchingbracket]=standout
    fi
else
    PROMPT='${debian_chroot:+($debian_chroot)}%n@%m:%~%(#.#.$) '
fi
unset color_prompt force_color_prompt

toggle_oneline_prompt(){
    if [ "$PROMPT_ALTERNATIVE" = oneline ]; then
        PROMPT_ALTERNATIVE=twoline
    else
        PROMPT_ALTERNATIVE=oneline
    fi
    configure_prompt
    zle reset-prompt
}
zle -N toggle_oneline_prompt
bindkey ^P toggle_oneline_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*|Eterm|aterm|kterm|gnome*|alacritty)
    TERM_TITLE=$'\e]0;${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%n@%m: %~\a'
    ;;
*)
    ;;
esac

precmd() {
    # Print the previously configured title
    print -Pnr -- "$TERM_TITLE"

    # Print a new line before the prompt, but only if it is not the first line
    if [ "$NEWLINE_BEFORE_PROMPT" = yes ]; then
        if [ -z "$_NEW_LINE_BEFORE_PROMPT" ]; then
            _NEW_LINE_BEFORE_PROMPT=1
        else
            print ""
        fi
    fi
}

# enable color support of ls, less and man, and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    export LS_COLORS="$LS_COLORS:ow=30;44:" # fix ls color for folders with 777 permissions

    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
    alias diff='diff --color=auto'
    alias ip='ip --color=auto'

    export LESS_TERMCAP_mb=$'\E[1;31m'     # begin blink
    export LESS_TERMCAP_md=$'\E[1;36m'     # begin bold
    export LESS_TERMCAP_me=$'\E[0m'        # reset bold/blink
    export LESS_TERMCAP_so=$'\E[01;33m'    # begin reverse video
    export LESS_TERMCAP_se=$'\E[0m'        # reset reverse video
    export LESS_TERMCAP_us=$'\E[1;32m'     # begin underline
    export LESS_TERMCAP_ue=$'\E[0m'        # reset underline

    # Take advantage of $LS_COLORS for completion as well
    zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"
    zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
fi

if [ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]; then
    . /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
    # change suggestion color
    ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=#999'
fi

# enable command-not-found if installed
if [ -f /etc/zsh_command_not_found ]; then
    . /etc/zsh_command_not_found
fi

# ==============================================================
# |                       custom script                       |
# ==============================================================

github_url_base="https://raw.githubusercontent.com/shi9uma/genshin/main"

# color
# ${RED}xxx${NC}
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

## function
cmd() {
    sed -n '/^# anchor$/,/^# end alias$/p' ~/.zshrc
}

tmp() {
    if [[ ! -d '/tmp/tmp' ]]; then
        mkdir -p '/tmp/tmp'
    fi
    cd /tmp/tmp
}

app() {
    if [[ ! -d '/home/app' ]]; then
        echo ${RED}"path /home/app invalid!"${NC}
    else
        cd /home/app
    fi
}

tsh() {
    new_shell_script=$1
    if [[ "$new_shell_script" != /* ]]; then
        new_shell_script="$PWD/$new_shell_script"
    fi
    if [[ ! -f "$new_shell_script" ]]; then
        touch $new_shell_script
        chmod +x $new_shell_script
        echo $new_shell_script
    fi
}

clean_history() {
    echo "" > ~/.zsh_history
    kill -9 $$
}

clean_docker() {
    docker rm `docker ps -a | grep Exited | awk '{ print $1 }'` > /dev/null 2>&1
    docker rmi `docker images | grep -i \<none\> | awk '{ print $3 }'` > /dev/null 2>&1

    docker images; echo ""
    docker ps -a
}

_curl() {
    curl -fLo $1 --create-dirs $2
}

password() {
    rename_path="$HOME/.genshin/password-generator.py"
    if [[ ! -f $rename_path ]]; then
        _curl $rename_path $github_url_base/script/02-encryption/01-password-generator.py
    fi
    python3 $rename_path "$@"
}

lcd() {
    lcd_path="$HOME/.genshin/lcd.py"
    if [[ ! -f $lcd_path ]]; then
        _curl $lcd_path $github_url_base/script/04-cmd-implementation/02-lcd.py
    fi
    if [[ "$1" == "cd" && ! -z "$2" ]]; then
        target_dir=$(python $lcd_path -pn "$2")
        cd "$target_dir"
    elif [[ "$1" == "l" ]]; then
        python3 $lcd_path -l
    elif [[ "$1" == "d" && ! -z "$2" ]]; then
        python3 $lcd_path -d -n "$2"
    elif [[ "$1" == "a" && ! -z "$2" ]]; then
        python3 $lcd_path -a "$2"
    else
        python3 $lcd_path "$@"
    fi
}

rename() {
    rename_path="$HOME/.genshin/interact-rename.py"
    if [[ ! -f $rename_path ]]; then
        _curl $rename_path $github_url_base/script/04-cmd-implementation/03-interact-rename.py
    fi
    python3 $rename_path "$@"
}

w2u() {
    windows_path_like="$1"
    unix_path=$(echo "$windows_path_like" | sed 's|\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')
    echo "$unix_path"
}

cx() {
    ip_status_path="$HOME/.genshin/ip-status.py"
    if [[ ! -f $ip_status_path ]]; then
        _curl $ip_status_path $github_url_base/script/03-network/03-ip-status.py
    fi
    python3 $ip_status_path "$@"
}

sd() {

    if [ $# -eq 0 ]; then
        echo "usage: sd {show|args}"
        return
    fi

    if [[ "$1" == "show" ]]; then
        echo "shodan search --fields ip_str,port,org,location ARGS | awk ' { print \"http://\"\$1\":\"\$2} '"
        return
    fi

    shodan_api_key_path="$HOME/.config/shodan/api_key"
    if [[ ! -f $shodan_api_key_path ]]; then
        echo ${RED}"shodan api key not found. run \"shodan init api_key\" first"${NC}
    else
        count=0
        shodan search --fields ip_str,port,org,location --separator "<>" "$@" | awk '{
            split($0, result, "<>");

            ip = result[1];
            if (ip == "") {
                next;
            }
            
            port = result[2];

            if (port == "443") {
                protocol = "https";
            } else {
                protocol = "http";
            }

            org = result[3];
            location = result[4];            

            print "| " protocol "://" ip ":" port;
            print "> " org;
            print "> " location;
            print "-----------------------------\n";

            count++;
        } END {
            print "total result: " count;
        }'
    fi
}

unblob() {
    unblob_path="$HOME/.genshin/unblob.sh"
    if [[ ! -f $unblob_path ]]; then
        _curl $unblob_path $github_url_base/code/shellscript/04-unblob.sh
        chmod +x $unblob_path
    fi
    cp $unblob_path .
    eval $PWD/unblob.sh $1
}

call_bridge() {
    call_bridge_path="$HOME/.genshin/call-bridge.sh"
    if [[ ! -f $call_bridge_path ]]; then
        _curl $call_bridge_path $github_url_base/script/04-cmd-implementation/04-call-bridge.sh
        chmod +x $call_bridge_path
    fi
    eval "$call_bridge_path $@"
}

update_zshrc() {
    zshrc_path="$HOME/.zshrc"
    _curl $zshrc_path $github_url_base/script/05-initial/.zshrc
}

## file, dir
if [[ -f "/home/game/minecraft/tool/rcon.py" ]]; then
    alias mc="python /home/game/minecraft/tool/rcon.py"
fi

if [[ -d "$HOME/repo" ]]; then
    alias repo="cd $HOME/repo"
fi

## export
proxy_ip_file="$HOME/.proxy_ip"
if [[ -f ~/.proxy_ip ]]; then
    export all_proxy="http://$(cat $proxy_ip_file):7890"
else
    if [[ -d "/home/wkyuu" ]]; then
        echo "${RED}proxy ip file: $proxy_ip_file not found, try ${GREEN}echo ip > \$proxy_ip_file${NC} ${NC}"
    fi
fi

### vim
export FZF_DEFAULT_COMMAND="rg --files"
export FZF_DEFAULT_OPTS="-m --height 40% --reverse --border --ansi --preview '(highlight -O ansi {} || cat {}) 2> /dev/null | head -500'"

### binary
os_type=$(uname -o)
export_path=$PATH
case $os_type in
    "Darwin")
        export_path=$HOME/.bin:$HOME/.local/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/opt/homebrew/opt/make/libexec/gnubin:$export_path
        alias python="python3"
        alias pip="pip3"

        alias typora="/Applications/Typora.app/Contents/MacOS/Typora"
        alias code="/Applications/VisualStudioCode.app/Contents/MacOS/Electron"
        alias bandizip="/Applications/Bandizip.app/Contents/MacOS/Bandizip"
        alias np="/Applications/Notepad--.app/Contents/MacOS/Notepad--"
        ;;
    "GNU/Linux")
        export_path=$HOME/.bin:$export_path:$HOME/.local/bin:$HOME/.cargo/bin
        ;;
esac
export PATH=$export_path


# anchor
# ==============================================================
# |                       custom alias                         |
# ==============================================================

# alias
alias l="ls -alh"
alias ll="ls -alh"
alias lt="ls -alht"
alias lss="ls -alhS"
alias cls="clear"
alias c="clear"
alias size="du -abh -d 1" # exclude file size under 1G: size -t 1G | exclude reg files: size --exclude=*backups*
alias x="curl"
alias xi="curl -I"
alias reg="grep -ir"
alias zshrc="source ~/.zshrc"
alias wky="sudo su wkyuu"
alias chwky="chown -R wkyuu:wkyuu"
alias transfer="sd http.favicon.hash:\"-620522584\""
# end alias
