$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding    # 英文用 utf-8
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)   # 中文用手动设置为 utf-8

# app export
$MINGW64PATH = "E:/lang/mingw64/bin"
$NODEJSPATH = "E:/lang/node"
$TYPORAPATH = "E:/software/Typora"
$GITPATH = "E:/toolkit/git/cmd"
$NOTEPADPATH = "E:/software/Notepad3"
$BTOPPATH = "E:/toolkit/btop4win"
$FDPATH = "E:/toolkit/fd"
$ADBPATH = "E:/toolkit/system-tools/android/01-platform-tools"
$FRIDAPATH = "E:/security/reverse/frida"
$DOTNETPATH = "E:/software/visual-studio/community/dotnet/net8.0/runtime"
$GRADLEPATH = "E:/lang/java/gradle-8.7/bin"

$VIMPATH = "E:/toolkit/vim/vim90"
$FZFPATH = "E:/toolkit/fzf"
$RIPGREPPATH = "E:/toolkit/ripgrep"

$env:PATH += ";$MINGW64PATH;$NODEJSPATH;$TYPORAPATH;$GITPATH;$NOTEPADPATH;$BTOPPATH;$FDPATH;$ADBPATH;$FRIDAPATH;$DOTNETPATH;$GRADLEPATH"
$env:PATH += ";$VIMPATH;$FZFPATH;$RIPGREPPATH"


# env export
$env:PIP_DOWNLOAD_CACHE = "E:/lang/python/pip-cache"
$env:GIT_EDITOR = "E:/toolkit/vim/vim90/vim.exe"
$env:FZF_DEFAULT_COMMAND = "rg --files"
$env:FZF_DEFAULT_OPTS="-m --height 40% --reverse --border --ansi"
$env:http_proxy="http://127.0.0.1:7890"
$env:https_proxy="http://127.0.0.1:7890"

# cancle native alias
Remove-Item Alias:ls

# Alias diy
Set-Alias np Notepad3
Set-Alias touch ni
Set-Alias grep findstr
Set-Alias p ipython

# diy script
function poweroff { Stop-Computer }
function reboot { Restart-Computer }

function password { python E:/project/04-flyMe2theStar/03-genshin/scripts/02-encryption/01-password-generator.py $args }
function rename { python E:/project/04-flyMe2theStar/03-genshin/scripts/04-cmd-implementation/03-interact-rename.py $args}
function encrypt { python E:/project/04-flyMe2theStar/03-genshin/scripts/02-encryption/03-ez-encrypt.py $args }
function cx { python E:/project/04-flyMe2theStar/03-genshin/scripts/03-network/03-ip-status.py $args }
function ftp { python E:/project/04-flyMe2theStar/03-genshin/scripts/03-network/02-fast-ftp-server.py $args }
function l { python E:/project/04-flyMe2theStar/03-genshin/scripts/04-cmd-implementation/01-ls-alh.py $args }
function ll { python E:/project/04-flyMe2theStar/03-genshin/scripts/04-cmd-implementation/01-ls-alh.py $args }
function ls { python E:/project/04-flyMe2theStar/03-genshin/scripts/04-cmd-implementation/01-ls-alh.py $args }
function la { python E:/project/04-flyMe2theStar/03-genshin/scripts/04-cmd-implementation/01-ls-alh.py $args --all }

function hash { certutil -hashfile $args }
function schale { ssh wkyuu@192.168.1.15 }
function pve { ssh wkyuu@192.168.1.9 }
function genshin { ssh wkyuu@192.168.9.1 }	# 172.20.7.231
function jiawa { ssh jiawa@172.20.6.123 }
function tree { E:/toolkit/tree/bin/tree.exe -N $args }
function magnet { echo magnet:?xt=urn:btih:$args }
function code { E:/software/vscode/binary/Code.exe --extensions-dir "E:/software/vscode/extensions" $args }
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
	$home_path = "C:/Users/wkyuu/Desktop"
    Set-Location -Path $home_path
}
function tmp {
    & print_old_dir
    $tmp_path = "E:/"
    $path = Join-Path -Path $tmp_path -ChildPath "tmp"
    if (-Not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path
    }
    Set-Location -Path $path
}
function lcd {
	$script_path = "E:/code/python/lcd.py"
    
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
        Write-Host "正在启动：Amd(R) Ryzen(TM)9 14900k + Windows 11 专业电竞战斗版" -ForegroundColor Yellow
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
		$args_xpath = $args -replace '\\', '/'
		wsl zsh -l -c "~/.genshin/cmd-implementation/call-bridge.sh $args_xpath"
    } else {
		Write-Host "Run you cmd after kali started." -ForegroundColor Yellow
		& kali
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
