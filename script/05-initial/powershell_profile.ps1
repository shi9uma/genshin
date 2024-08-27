$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding    # 英文用 utf-8
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)   # 中文用手动设置为 utf-8

# app export
$MINGW64PATH = "d:/lang/mingw64/bin"
$NODEJSPATH = "d:/lang/node"
$TYPORAPATH = "d:/software/Typora"
$GITPATH = "d:/bin/git/cmd"
$NOTEPADPATH = "d:/software/kate/bin"
$BTOPPATH = "d:/bin/btop4win"
$FDPATH = "d:/bin/fd"
$ADBPATH = "d:/bin/system-tools/android/01-platform-tools"
$FRIDAPATH = "d:/security/reverse/frida"
$DOTNETPATH = "d:/software/visual-studio/community/dotnet/net8.0/runtime"
$GRADLEPATH = "d:/lang/java/gradle-8.7/bin"

$VIMPATH = "d:/bin/vim/vim90"
$FZFPATH = "d:/bin/fzf"
$RIPGREPPATH = "d:/bin/ripgrep"

$env:PATH += "$MINGW64PATH;$NODEJSPATH;$TYPORAPATH;$GITPATH;$NOTEPADPATH;$BTOPPATH;$FDPATH;$ADBPATH;$FRIDAPATH;$DOTNETPATH;$GRADLEPATH"
$env:PATH += "$VIMPATH;$FZFPATH;$RIPGREPPATH"


# env export
$env:PIP_DOWNLOAD_CACHE = "d:/lang/python/pip-cache"
$env:GIT_EDITOR = "d:/bin/vim/vim90/vim.exe"
$env:FZF_DEFAULT_COMMAND = "rg --files"
$env:FZF_DEFAULT_OPTS="-m --height 40% --reverse --border --ansi"
$env:http_proxy="http://127.0.0.1:7890"
$env:https_proxy="http://127.0.0.1:7890"

# cancle native alias
Remove-Item Alias:ls

# Alias diy
Set-Alias np kate
Set-Alias touch ni
Set-Alias grep findstr
Set-Alias p ipython

# diy script
function poweroff { Stop-Computer }
function reboot { Restart-Computer }

function password { python d:/project/04-flyMe2theStar/03-genshin/script/02-encryption/01-password-generator.py $args }
function rename { python d:/project/04-flyMe2theStar/03-genshin/script/04-cmd-implementation/03-interact-rename.py $args}
function encrypt { python d:/project/04-flyMe2theStar/03-genshin/script/02-encryption/03-ez-encrypt.py $args }
function cx { python d:/project/04-flyMe2theStar/03-genshin/script/03-network/03-ip-status.py $args }
function ftp { python d:/project/04-flyMe2theStar/03-genshin/script/03-network/02-fast-ftp-server.py $args }
function l { python d:/project/04-flyMe2theStar/03-genshin/script/04-cmd-implementation/01-ls-alh.py $args }
function ll { python d:/project/04-flyMe2theStar/03-genshin/script/04-cmd-implementation/01-ls-alh.py $args }
function ls { python d:/project/04-flyMe2theStar/03-genshin/script/04-cmd-implementation/01-ls-alh.py $args }
function la { python d:/project/04-flyMe2theStar/03-genshin/script/04-cmd-implementation/01-ls-alh.py $args --all }

function hash { certutil -hashfile $args }
function pve { ssh wkyuu@192.168.9.3 }
function genshin { ssh wkyuu@192.168.9.1 }	# 172.20.7.231
function tree { d:/bin/tree/bin/tree.exe -N $args }
function magnet { echo magnet:?xt=urn:btih:$args }
function code { d:/software/visual-studio-code/binary/Code.exe --extensions-dir "d:/software/visual-studio-code/extension" $args }
function rmrf { Remove-Item -Recurse -Force $args }
function xpath {
    $convertedPath = $args -replace '\\', '/'
    Write-Host $convertedPath -ForegroundColor Yellow
}
function exp { 
	if ($args[0]) {
		& explorer $args[0]
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
	$script_path = "d:/project/04-flyMe2theStar/03-genshin/script/04-cmd-implementation/02-lcd.py"
    
    if ($args[0] -eq "cd" -and $args[1]) {
        $targetDir = python $script_path -pn $args[1] | Select-String -Pattern '/S+$' | ForEach-Object { $_.Matches[0].Value }
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
        Write-Host "Starting Intel 14900k + Windows 11 专业电竞战斗版 instance in background." -ForegroundColor Yellow
    }
}
function kalidown {
    $running = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "wsl.exe" } | Select-Object -ExpandProperty CommandLine
    if ($running -like "*kali*") {
		wsl --shutdown kali
		Write-Host "Shutting down Kali WSL instance." -ForegroundColor Yellow
    } else {
		Write-Host "no kali wsl instance running, type kali to start one." -ForegroundColor Yellow
    }
}
function k {
	$running = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "wsl.exe" } | Select-Object -ExpandProperty CommandLine
    if ($running -like "*kali*") {
		wsl zsh -l -c "~/.genshin/cmd-implementation/call-bridge.sh $args"
    } else {
		& kali
		Write-Host "run you cmd after kali started." -ForegroundColor Yellow
    }
}
# frida
function frida {
    if ($env:VIRTUAL_ENV -and (python -c "import sys; print(sys.prefix == sys.base_prefix)")) {
        & "$FRIDAPATH/frida/Scripts/frida.exe" $args
    } else {
        $currentPath = Get-Location
        Set-Location -Path $FRIDAPATH
        & "./frida/Scripts/Activate"
        Write-Host "`n------------------------------------------------" -ForegroundColor Yellow
        Write-Host " Activated Frida venv environment | $FRIDAPATH" -ForegroundColor Yellow
        Write-Host " Type 'deactivate' to exit" -ForegroundColor Yellow
        Write-Host "------------------------------------------------`n" -ForegroundColor Yellow
        Set-Location -Path $currentPath
    }
}