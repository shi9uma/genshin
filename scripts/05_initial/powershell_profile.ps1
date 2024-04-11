$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# app export
$MINGW64PATH = "E:/lang/mingw64/bin"
$NODEJSPATH = "E:/lang/node"
$TYPORAPATH = "E:/software/Typora"
$GITPATH = "E:/toolkit/git/cmd"
$NOTEPADPATH = "E:/software/Notepad3"
$VIMPATH = "E:/toolkit/vim/vim90"
$ASTYLEPATH = "E:/toolkit/vim/scripts/astyle"
$CTAGSPATH = "E:/toolkit/vim/scripts/ctags"
$FDPATH = "E:/toolkit/fd"
$ADBPATH = "E:/toolkit/system-init/android-root/01_platform-tools"
$FRIDAPATH = "E:/security/reverse/frida"
$DOTNETPATH = "E:/software/visual-studio/community/dotnet/net8.0/runtime"
$GRADLEPATH = "E:/lang/java/gradle-8.7/bin"

$env:PATH += ";$MINGW64PATH;$NODEJSPATH;$TYPORAPATH;$GITPATH;$NOTEPADPATH;$VIMPATH;$ASTYLEPATH;$CTAGSPATH;$FDPATH;$ADBPATH;$FRIDAPATH;$DOTNETPATH;$GRADLEPATH"

# env export
$env:PIP_DOWNLOAD_CACHE = "E:/lang/python/pip-cache"
$env:http_proxy="http://127.0.0.1:7890"
$env:https_proxy="http://127.0.0.1:7890"


# Alias diy
Set-Alias np Notepad3
Set-Alias touch ni
Set-Alias grep findstr
Set-Alias p ipython

# diy script
function poweroff { Stop-Computer }
function reboot { Restart-Computer }
function hash { certutil -hashfile $args }
function password { python E:/code/python/password.py $args }
function itx { ssh -p 6022 wkyuu@majo.im }
function tree { E:/toolkit/tree/bin/tree.exe -N $args }
function rename { python E:/code/python/interact_rename.py $args}
function ftp { python E:/code/python/ftp.py $args }
function magnet { echo magnet:?xt=urn:btih:$args }
function code { E:/software/vscode/binary/Code.exe --extensions-dir "E:/software/vscode/extensions" $args }
function rmrf { Remove-Item -Recurse -Force $args }
function ll { python E:/code/python/ls_alh.py $args }
function home {
	$current_path = Get-Location
	$home_path = "C:/Users/wkyuu/Desktop"
    Write-Host "old pwd > $current_path" -ForegroundColor Blue
    Set-Location -Path $home_path
}
function tmp {
    $tmp_path = "E:/"
	$current_path = Get-Location
    $path = Join-Path -Path $tmp_path -ChildPath "tmp"
    if (-Not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path
    }
    Write-Host "old pwd > $current_path" -ForegroundColor Blue
    Set-Location -Path $path
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
