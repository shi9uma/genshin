$pathsToAdd = @(
    "",
    "C:\ExamplePath2",
    "C:\ExamplePath3"
)

function Add-EnvironmentVariable {
    param (
        [string]$Path
    )
    
    $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
    if ($currentPath -notlike "*$Path*") {
        $newPath = $currentPath + ";" + $Path
        [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Output "path added: $Path"
    } else {
        Write-Output "path already existed: $Path"
    }
}

foreach ($path in $pathsToAdd) {
    Add-EnvironmentVariable -Path $path
}
