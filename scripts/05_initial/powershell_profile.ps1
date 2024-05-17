$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding    # 英文用 utf-8
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(936)   # 中文用手动设置为 utf-8

# app export
$MINGW64PATH = "E:/lang/mingw64/bin"
$NODEJSPATH = "E:/lang/node"
$TYPORAPATH = "E:/software/Typora"
$GITPATH = "E:/toolkit/git/cmd"
$NOTEPADPATH = "E:/software/Notepad3"
$FDPATH = "E:/toolkit/fd"
$ADBPATH = "E:/toolkit/system_tools/android_root/01_platform_tools"
$FRIDAPATH = "E:/security/reverse/frida"
$DOTNETPATH = "E:/software/visual-studio/community/dotnet/net8.0/runtime"
$GRADLEPATH = "E:/lang/java/gradle-8.7/bin"

$VIMPATH = "E:/toolkit/vim/vim90"
$FZFPATH = "E:/toolkit/fzf"
$RIPGREPPATH = "E:/toolkit/ripgrep"

$env:PATH += ";$MINGW64PATH;$NODEJSPATH;$TYPORAPATH;$GITPATH;$NOTEPADPATH;$FDPATH;$ADBPATH;$FRIDAPATH;$DOTNETPATH;$GRADLEPATH"
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
function hash { certutil -hashfile $args }
function password { python E:/code/python/password_generator.py $args }
function tree { E:/toolkit/tree/bin/tree.exe -N $args }
function rename { python E:/code/python/interact_rename.py $args}
function encrypt { python E:/code/python/encrypt.py $args }
function ftp { python E:/code/python/ftp.py $args }
function magnet { echo magnet:?xt=urn:btih:$args }
function code { E:/software/vscode/binary/Code.exe --extensions-dir "E:/software/vscode/extensions" $args }
function rmrf { Remove-Item -Recurse -Force $args }
function ls { python E:/code/python/ls_alh.py $args }
function l { python E:/code/python/ls_alh.py $args }
function la { python E:/code/python/ls_alh.py $args --all }
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
        $targetDir = python $script_path -pn $args[1] | Select-String -Pattern '\S+$' | ForEach-Object { $_.Matches[0].Value }
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
        Write-Host "Starting Kali WSL instance in background." -ForegroundColor Yellow
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
