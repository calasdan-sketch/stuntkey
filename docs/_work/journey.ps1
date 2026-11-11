$ErrorActionPreference = "Continue"
$t = Join-Path $env:TEMP "sk-journey-home"
Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$t\AppData\Roaming","$t\AppData\Local","$t\kc","$t\proj" | Out-Null
$env:HOME=$t; $env:USERPROFILE=$t; $env:APPDATA="$t\AppData\Roaming"; $env:LOCALAPPDATA="$t\AppData\Local"
Get-ChildItem Env: | ? { $_.Name -like 'STUNTKEY_*' } | % { Remove-Item "Env:$($_.Name)" }
$env:STUNTKEY_KEYCHAIN = "file:$t\kc"
$env:PYTHONIOENCODING = "utf-8"
$sk = Join-Path $env:TEMP "sk-venv\Scripts\stuntkey.exe"
$out = "C:\Users\danie\oathkey\docs\_work\e2e-journey.md"
$o = Join-Path $env:TEMP "sk-wheel"; Remove-Item -Recurse -Force $o -ErrorAction SilentlyContinue
Push-Location C:\Users\danie\oathkey; python -m build --wheel --no-isolation --outdir $o 2>&1 | Out-Null; Pop-Location
& (Join-Path $env:TEMP "sk-venv\Scripts\python.exe") -m pip install --force-reinstall --no-deps --no-index (Get-ChildItem $o\stuntkey-0.9.2-*.whl).FullName 2>&1 | Out-Null
Set-Location "$t\proj"
"# StuntKey 0.9.2 end-to-end journey`n`nWheel built offline, installed with --no-deps into a TEMP venv ($env:TEMP\sk-venv), run in an isolated HOME ($t) with STUNTKEY_KEYCHAIN=file:<temp>\kc and fake keys only. Real ~/.stuntkey, Credential Manager and activity log untouched.`n" | Set-Content -Encoding utf8 $out
function Step($title, $cmdline, [scriptblock]$body) {
  $r = & $body 2>&1 | Out-String -Width 200
  $code = $LASTEXITCODE
  Add-Content -Encoding utf8 $out ("## " + $title + "`n`n``````" + "`n> " + $cmdline + "`n" + $r.TrimEnd() + "`n(exit code " + $code + ")`n``````" + "`n")
}
Step "version" "stuntkey --version" { & $sk --version }
Step "try (practice)" "stuntkey try --auto" { & $sk try --auto }
Step "get example.com from stdin" "echo <fake key> | stuntkey get example.com --key-from-stdin" { "fake_EXAMPLEKEY_0123456789abcdefABCDEF" | & $sk get example.com --key-from-stdin }
Step "status" "stuntkey status" { & $sk status }
Step "doctor" "stuntkey doctor" { & $sk doctor }
$envtext = "OPENAI_API_KEY=sk-FAKE0000000000000000000000000000000000000000`nGITHUB_TOKEN=ghp_FAKE00000000000000000000000000000000`nSOME_UNRELATED_SETTING=hello`n"
[IO.File]::WriteAllText("$t\proj\sample.env", $envtext)
Step "import a sample .env" "stuntkey import sample.env --yes" { & $sk import sample.env --yes }
Step "list stored (status again)" "stuntkey status" { & $sk status }
Step "forget example.com" "stuntkey forget example.com --yes" { & $sk forget example.com --yes }
Step "audit before any call (empty log)" "stuntkey audit" { & $sk audit }
$venvpy = Join-Path $env:TEMP "sk-venv\Scripts\python.exe"
Step "write 3 synthetic log entries the way the broker does (library call in the venv)" "python -c AuditLog(...).write(...) x3" { & $venvpy -c "from stuntkey import broker,remote; import os; a=broker.AuditLog(os.path.join(remote.home_dir(),'audit.log'));[a.write({'service':'example','method':'GET','host':'api.example.com','path':'/v'+str(i),'status':200,'result':'ok'}) for i in range(3)]; print(a.verify_detail())" }
Step "audit (verify keyed chain)" "stuntkey audit" { & $sk audit }
Step "audit verify (json)" "stuntkey audit verify --json" { & $sk audit verify --json }
Step "audit show" "stuntkey audit show" { & $sk audit show }
Step "start" "stuntkey start" { & $sk start }
# the page: serve in the background, take the one-time link, fetch the page with Python
$log = "$t\serve.out"
$p = Start-Process -FilePath $sk -ArgumentList "serve","--port","0" -RedirectStandardOutput $log -RedirectStandardError "$t\serve.err" -PassThru -WindowStyle Hidden
Start-Sleep 5
$url = (Select-String -Path $log -Pattern 'http://127.0.0.1:\d+/\?c=\S+').Matches.Value | Select -First 1
$py = @"
import http.client, re, sys
url = sys.argv[1]
m = re.match(r'http://127.0.0.1:(\d+)(/.*)', url); port = int(m.group(1)); path = m.group(2)
def get(path, cookie=None):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    h = {'Host': '127.0.0.1:%d' % port}
    if cookie: h['Cookie'] = cookie
    c.request('GET', path, headers=h); r = c.getresponse(); return r.status, r.read().decode(), r
s, b, r = get('/')
print('GET / with no cookie ->', s)
s, b, r = get(path)
print('GET one-time link ->', s, 'Location:', r.getheader('Location'), 'cookie set:', bool(r.getheader('Set-Cookie')))
ck = r.getheader('Set-Cookie').split(';')[0]
s, b, r = get('/', ck)
print('GET / with cookie ->', s, 'bytes', len(b))
print('placeholders left:', '{{status_json}}' in b, '{{version}}' in b)
print('version text:', re.search(r'id="ver">([^<]*)<', b) is not None, '0.9.2' in b)
print('status json:', re.search(r'id="sk-status">(.*?)</script>', b, re.S).group(1)[:200])
print('mentions stuntkey try:', 'stuntkey try' in b, '| mentions selftest:', 'stuntkey selftest' in b)
s, b, r = get(path)
print('one-time link used a second time ->', s)
"@
[IO.File]::WriteAllText("$t\page.py", $py)
Step "serve: the page" "stuntkey serve  (then fetch the one-time link)" { "link line: " + ($url -replace 'c=\S+','c=<one-time>'); python "$t\page.py" $url }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Step "tamper test: edit one log line, then verify must fail" "(edit audit.log in the isolated home) ; stuntkey audit" { $f="$t\kc\audit.log"; if(-not (Test-Path $f)){ $f=(Get-ChildItem $t -Recurse -Filter audit.log | select -First 1).FullName }; "log file: $f"; $c=[IO.File]::ReadAllText($f); [IO.File]::WriteAllText($f,$c.Replace("/v1","/v9")); & $sk audit; "--- restoring is not possible; this home is thrown away ---" }
"DONE" | Add-Content "$t\journey.done"
