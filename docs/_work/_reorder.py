import re
p = r"C:\Users\danie\oathkey\docs\_work\journey.ps1"
s = open(p, encoding="utf-8").read()
lines = s.split("\n")
tamper = [l for l in lines if l.startswith('Step "tamper test')]
lines = [l for l in lines if not l.startswith('Step "tamper test')]
out = []
for l in lines:
    if l.startswith("Stop-Process"):
        out.append(l)
        out += tamper
        continue
    out.append(l)
s = "\n".join(out)
rebuild = '''$o = Join-Path $env:TEMP "sk-wheel"; Remove-Item -Recurse -Force $o -ErrorAction SilentlyContinue
Push-Location C:\\Users\\danie\\oathkey; python -m build --wheel --no-isolation --outdir $o 2>&1 | Out-Null; Pop-Location
& (Join-Path $env:TEMP "sk-venv\\Scripts\\python.exe") -m pip install --force-reinstall --no-deps --no-index (Get-ChildItem $o\\stuntkey-0.9.2-*.whl).FullName 2>&1 | Out-Null
'''
s = s.replace('Set-Location "$t\\proj"', rebuild + 'Set-Location "$t\\proj"', 1)
open(p, "w", encoding="utf-8").write(s)
print("ok", "tamper" in s)
