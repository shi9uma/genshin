$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding    # english use utf-8
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)   # chinese change to utf-8 handly

# app export
###################### lang ######################
$GRADLEPATH = "d:/lang/java/gradle-8.7/bin"
$MINGW64PATH = "d:/lang/mingw64/bin"
$NODEJSPATH = "d:/lang/node"

$env:PATH += "$GRADLEPATH;" + `
"$MINGW64PATH;" + `
"$NODEJSPATH;"

$env:PIP_DOWNLOAD_CACHE = "d:/lang/python/pip-cache"

###################### bin ######################
$BTOPPATH = "d:/bin/btop4win"
$FDPATH = "d:/bin/fd"
$FFMPEGPATH = "d:/bin/ffmpeg"
$FZFPATH = "d:/bin/fzf"
$GITPATH = "d:/bin/git/cmd"
$NMAPPATH = "d:/bin/nmap"
$RIPGREPPATH = "d:/bin/ripgrep"
$TREEPATH = "d:/bin/tree/bin"
$VIMPATH = "d:/bin/vim/vim90"

$env:PATH += "$BTOPPATH;" + `
"$FDPATH;" + `
"$FFMPEGPATH;" + `
"$FZFPATH;" + `
"$GITPATH;" + `
"$NMAPPATH;" + `
"$RIPGREPPATH;" + `
"$TREEPATH;" + `
"$VIMPATH;"

$env:GIT_EDITOR = "$VIMPATH/vim.exe"
$env:FZF_DEFAULT_COMMAND = "rg --files"
$env:FZF_DEFAULT_OPTS="-m --height 40% --reverse --border --ansi"

###################### software ######################
$NOTEPAD4PATH = "d:/software/notepad4"
$POTPLAYERPATH = "d:/software/potplayer"
$SUMATRAPATH = "d:/software/sumatra-pdf"
$TYPORAPATH = "d:/software/typora"
$XNVIEWPATH = "d:/software/xnview"

$env:PATH += "$NOTEPAD4PATH;" + `
"$POTPLAYERPATH;" + `
"$SUMATRAPATH;" + `
"$TYPORAPATH;" + `
"$XNVIEWPATH;"

Set-Alias play PotPlayerMini64
Set-Alias np Notepad4
Set-Alias pdf sumatrapdf
Set-Alias img xnviewmp

###################### sec ######################
$ADBPATH = "d:/sec/android/android-platform-tool"
$BURPSUITEPATH = "d:/sec/burpsuite"
$FRIDAPATH = "d:/sec/frida"
$IDAPATH = "d:/sec/ida"
$JADXPATH = "d:/sec/jadx"
$MOBAXTERMPATH = "d:/sec/mobaxterm-portable"
$WINHEXPATH = "d:/sec/winhex"
$WIRESHARKPATH = "d:/sec/wireshark"

$env:PATH += "$ADBPATH;" + `
"$BURPSUITEPATH;" + `
"$FRIDAPATH;" + `
"$IDAPATH;" + `
"$JADXPATH;" + `
"$MOBAXTERMPATH;" + `
"$WINHEXPATH;" + `
"$WIRESHARKPATH;"

Set-Alias ida ida64
Set-Alias moba mobaxterm
Set-Alias winhex xwforensics64
Set-Alias wireshark WiresharkPortable64

# env export
$env:http_proxy="http://127.0.0.1:7890"
$env:https_proxy="http://127.0.0.1:7890"

# cancle native alias
Remove-Item Alias:ls

# Alias diy
Set-Alias touch ni
Set-Alias grep findstr
Set-Alias p ipython
Set-Alias mgmt compmgmt.msc
Set-Alias reg regedit

# diy script
function poweroff { Stop-Computer }
function reboot { Restart-Computer }

function password { python d:/project/04-flyMe2theStar/03-genshin/code/python/08-password-generator.py $args }
function rename { python d:/project/04-flyMe2theStar/03-genshin/code/python/14-interact-rename.py $args}
function encrypt { python d:/project/04-flyMe2theStar/03-genshin/code/python/02-ez-encrypt.py $args }
function cx { python d:/project/04-flyMe2theStar/03-genshin/code/python/09-ip-status.py $args }
function ftp { python d:/project/04-flyMe2theStar/03-genshin/code/python/16-fast-ftp-server.py $args }
function l { python d:/project/04-flyMe2theStar/03-genshin/code/python/12-ls-alh.py $args }
function ll { python d:/project/04-flyMe2theStar/03-genshin/code/python/12-ls-alh.py $args }
function ls { python d:/project/04-flyMe2theStar/03-genshin/code/python/12-ls-alh.py $args }
function la { python d:/project/04-flyMe2theStar/03-genshin/code/python/12-ls-alh.py $args --all }
function lt { python d:/project/04-flyMe2theStar/03-genshin/code/python/12-ls-alh.py $args -s time }
function lss { python d:/project/04-flyMe2theStar/03-genshin/code/python/12-ls-alh.py $args -s size }

function genshin { ssh genshin-wkyuu }
function pve { ssh pve-wkyuu }
function schale { ssh schale-wkyuu }

function hash { certutil -hashfile $args }
function tree { d:/bin/tree/bin/tree.exe -N -h $args }
function geek { d:/bin/geek.exe }
function env { Start-Process powershell "-Command & {rundll32 sysdm.cpl,EditEnvironmentVariables}" -Verb RunAs }
function magnet { echo magnet:?xt=urn:btih:$args }
function code { d:/software/visual-studio-code/binary/Code.exe --extensions-dir "d:/software/visual-studio-code/extension" $args }
function rmrf { Remove-Item -Recurse -Force $args }
function xpath {
    $convertedPath = $args -replace '\\', '/'
    Write-Host $convertedPath -ForegroundColor Yellow
}
function exp { 
    if ($args[0]) {
        $convertedPath = $args[0] -replace '/', '\'
        & explorer $convertedPath
    } else {
        & explorer .
    }
}
function print_old_dir {
    $old_dir = Get-Location
    Write-Host "old pwd > $old_dir" -ForegroundColor Blue
}
function home {
    & print_old_dir
    $home_path = "c:/users/wkyuu/desktop"
    Set-Location -Path $home_path
}
function download {
    & print_old_dir
    $download_path = "e:/download"
    Set-Location -Path $download_path
}
function tmp {
    & print_old_dir
    $tmp_path = "e:/"
    $path = Join-Path -Path $tmp_path -ChildPath "tmp"
    if (-Not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path
    }
    Set-Location -Path $path
}
function lcd {
    $script_path = "d:/project/04-flyMe2theStar/03-genshin/code/python/13-lcd.py"
    
    if ($args[0] -eq "cd" -and $args[1]) {
        $targetDir = python $script_path -pn $args[1] | Select-String -Pattern '([A-Za-z]:\/[^\r\n]+)' | ForEach-Object { $_.Matches[0].Value }
        Set-Location $targetDir
    } elseif ($args[0] -eq "l") {
        python $script_path -l
    } elseif ($args[0] -eq "d" -and $args[1]) {
        python $script_path -d -n $args[1]
    } elseif ($args[0] -eq "a" -and $args[1]) {
        python $script_path -a $args[1]
    } else {
        python $script_path $args
    }
}
# wsl
function kali {
    $shell = New-Object -ComObject WScript.Shell
    $running = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "wsl.exe" } | Select-Object -ExpandProperty CommandLine
    if ($running -like "*kali*") {
        wsl --distribution kali
    } else {
        $shell.Run("wsl --distribution kali", 0)
        Write-Host "Starting AMD 14900k + Windows 11 instance in background." -ForegroundColor Yellow
    }
}
function kalidown {
    $running = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "wsl.exe" } | Select-Object -ExpandProperty CommandLine
    if ($running -like "*kali*") {
        wsl --shutdown kali
        Write-Host "shutting down AMD 14900k + Windows 11 instance." -ForegroundColor Yellow
        $service = Get-Service -Name "WSLKaliService" -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name "WSLKaliService"
            Write-Host "WSL Kali service stopped." -ForegroundColor Yellow
        }
    } else {
        Write-Host "no AMD 14900k + Windows 11 instance running, type kali to start one." -ForegroundColor Yellow
    }
}
function k {
    $running = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "wsl.exe" } | Select-Object -ExpandProperty CommandLine
    if ($running -like "*kali*") {
        wsl zsh -l -c "~/.genshin/call-bridge.sh $args"
    } else {
        & kali
        Write-Host "run you cmd after kali started." -ForegroundColor Yellow
    }
}
# frida
function frida {
    if ($env:VIRTUAL_ENV -and (python -c "import sys; print(sys.prefix == sys.base_prefix)")) {
        & "$FRIDAPATH/venv-frida/Scripts/frida.exe" $args
    } else {
        $currentPath = Get-Location
        Set-Location -Path $FRIDAPATH
        & "./venv-frida/Scripts/Activate"
        Write-Host "`n------------------------------------------------" -ForegroundColor Yellow
        Write-Host " Activated Frida venv environment | $FRIDAPATH" -ForegroundColor Yellow
        Write-Host " Type 'deactivate' to exit" -ForegroundColor Yellow
        Write-Host "------------------------------------------------`n" -ForegroundColor Yellow
        Set-Location -Path $currentPath
    }
}