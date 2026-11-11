$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$root = 'C:\Users\danie\oathkey'
$out = "$root\docs\_work\shots"
$pages = @{ 'web' = "$root\stuntkey\web\index.html"; 'site' = "$root\docs\site\index.html"; 'how' = "$root\docs\site\how-it-works.html"; 'first' = "$root\docs\site\add-your-first-key.html" }
# Chrome headless will not go below ~500px wide, so 390px is rendered inside an iframe of exactly 390px.
foreach ($k in $pages.Keys) {
  $u = "file:///" + ($pages[$k] -replace '\\', '/')
  $h = "$out\_h-$k.html"
  Set-Content -Path $h -Encoding utf8 -Value "<!doctype html><body style='margin:0;background:#888'><iframe src='$u' style='border:0;width:390px;height:3000px;display:block;background:#fff'></iframe>"
  foreach ($w in @(1280, 390)) {
    foreach ($scheme in @('light', 'dark')) {
      $cs = if ($scheme -eq 'dark') { 0 } else { 1 }
      $f = "$out\$k-$w-$scheme.png"
      $target = if ($w -eq 390) { "file:///" + ($h -replace '\\', '/') } else { $u }
      $size = if ($w -eq 390) { "500,3000" } else { "1280,2600" }
      & $chrome --headless=new --disable-gpu --hide-scrollbars "--blink-settings=preferredColorScheme=$cs" "--window-size=$size" "--screenshot=$f" $target 2>$null | Out-Null
    }
  }
}
dir $out -Filter *.png | select Name, Length
