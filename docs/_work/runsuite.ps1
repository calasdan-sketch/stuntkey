param([string]$Name="run1",[string]$Keychain="",[string]$Args2="-q")
$t = Join-Path $env:TEMP ("sk-home-" + $Name)
Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $t | Out-Null
$env:HOME=$t; $env:USERPROFILE=$t; $env:APPDATA=(Join-Path $t "AppData\Roaming"); $env:LOCALAPPDATA=(Join-Path $t "AppData\Local")
New-Item -ItemType Directory -Force $env:APPDATA,$env:LOCALAPPDATA | Out-Null
Get-ChildItem Env: | Where-Object { $_.Name -like 'STUNTKEY_*' } | ForEach-Object { Remove-Item "Env:$($_.Name)" }
if ($Keychain) { $env:STUNTKEY_KEYCHAIN=$Keychain }
Set-Location C:\Users\danie\oathkey
$out = "C:\Users\danie\oathkey\docs\_work\suite-$Name.txt"
$a = $Args2 -split ' '
python -m pytest @a 2>&1 | Out-File -Encoding utf8 $out
"DONE" | Add-Content $out
