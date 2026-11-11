"""Rebuild the StuntKey brand pages from docs/_work/brand_src.

Writes: docs/site/styles.css, docs/site/*.html, stuntkey/web/index.html.
The crest is the real Calas logo PNG (docs/site/favicon.png), embedded as a mask.
Run:  python docs/_work/build_brand.py
Importing it writes nothing: read OUT ({path: text}), or call write_all().
"""
import base64
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "docs", "_work", "brand_src")
SITE = os.path.join(ROOT, "docs", "site")
HOME = "https://calasautomations.com/devtools/stuntkey/"
FONTS = ('<link rel="preconnect" href="https://fonts.googleapis.com">'
         '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
         '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400'
         '&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">')


def rd(p):
    with open(p, encoding="utf8") as f:
        return f.read()


OUT = {}   # "docs/site/index.html" -> text, filled by wr(); nothing is written on import


def wr(p, s):
    OUT[os.path.relpath(p, ROOT).replace(os.sep, "/")] = s


def write_all():
    """Write every collected page to disk (what `python build_brand.py` does)."""
    for rel, s in OUT.items():
        p = os.path.join(ROOT, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf8", newline="\n") as f:
            f.write(s)


with open(os.path.join(SITE, "favicon.png"), "rb") as f:
    CREST = base64.b64encode(f.read()).decode()
css = rd(os.path.join(SRC, "styles.src.css")).replace("@@CREST@@", CREST)
wr(os.path.join(SITE, "styles.css"), css)

NAV = [("index.html", "Home"), ("how-it-works.html", "How it works"), ("add-your-first-key.html", "Add your first key")]


def page(fname, title, desc, body, hero=False):
    nav = "".join('<a href="%s"%s>%s</a>' % (h, ' aria-current="page"' if h == fname else "", t) for h, t in NAV)
    nav += '<a href="https://github.com/calasdan-sketch/stuntkey">GitHub</a>'
    lock = ('<span class="crest" aria-hidden="true"></span><span><span class="name">StuntKey</span>'
            '<span class="sub">BY CALAS AUTOMATIONS</span></span>')
    return f"""<!doctype html>
<html lang="en-CA">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{desc}">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#0B2E45">
<link rel="canonical" href="{HOME}{'' if fname == 'index.html' else fname}">
<link rel="icon" type="image/png" href="favicon.png">
{FONTS}
<link rel="stylesheet" href="styles.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="bar"><div class="in">
  <a class="lock" href="index.html" aria-label="StuntKey by Calas Automations, home">{lock}</a>
  <nav aria-label="Primary">{nav}</nav>
</div></header>
<main id="main">
{body}
</main>
<footer class="foot"><div class="in">
  <a class="lock" href="index.html" aria-label="StuntKey home">{lock}</a>
  <nav aria-label="Footer">{nav}<a href="https://pypi.org/project/stuntkey/">PyPI</a><a href="https://github.com/calasdan-sketch/stuntkey/blob/main/docs/THREAT_MODEL.md">Threat model</a><a href="https://calasautomations.com/devtools/">All dev tools</a></nav>
  <p class="fine">Free and open source, MIT licence. Python standard library only. Formerly OathKey and SafeEasyAPI.<br>
  &copy; Calas Automations Inc., Winnipeg, Manitoba. Questions: <a href="mailto:office@calasautomations.com">office@calasautomations.com</a>. Security problem? <a href="mailto:security@calasautomations.com">security@calasautomations.com</a></p>
</div></footer>
</body>
</html>
"""


INDEX = """<section class="hero"><div class="wrap">
  <p class="eyebrow">Free and open source &middot; Windows, Mac, Linux</p>
  <h1>Your AI uses your keys. <em>The key stays out of its environment.</em></h1>
  <p class="lede">StuntKey keeps your API keys in your computer's own keychain. Your AI works with a stand-in, a stunt double, and StuntKey adds the real key on the way out.</p>
  <div class="ctas"><a class="btn gold" href="add-your-first-key.html">Add your first key</a><a class="btn ghost" href="how-it-works.html">How it works</a></div>
</div></section>
<section><div class="wrap">
  <h2>Why it matters</h2>
  <div class="grid">
    <div class="card"><h3>Keys stay hidden</h3><p>Used through the broker, the key never enters your AI's environment. A key it does not hold is much harder to leak.</p></div>
    <div class="card"><h3>Spending limits</h3><p>Set a daily limit on each key, and stop everything with one command.</p></div>
    <div class="card"><h3>Fix a leak fast</h3><p>Leaked one? <code>stuntkey panic openai</code> walks you through it, step by step.</p></div>
  </div>
</div></section>
<section class="sunk"><div class="wrap">
  <h2>Start in one minute</h2>
  <div class="cmd"><code>pip install stuntkey</code></div>
  <div class="cmd"><code>stuntkey start</code></div>
  <p class="say">The second command checks your computer, looks for keys lying around, and tells you what to do next. <a href="add-your-first-key.html">Full walk-through</a>.</p>
</div></section>
<section><div class="wrap">
  <h2>Honest about the limits</h2>
  <div class="note"><p>StuntKey lowers the risk. It does not remove it. It is beta and has not had an independent security review yet.</p>
  <p>It cannot stop an AI misusing a key it is allowed to use, so give each key only the permissions it needs. It does not protect against a virus already running as you: anything running as you can read your keychain. The Claude Code hook blocks common leaks, but Cursor, Codex, Gemini and Claude Desktop have no such hook for their file tools, screenshots and the clipboard are not covered, and code that hides what it does can get past pattern checks. Details: the <a href="https://github.com/calasdan-sketch/stuntkey/blob/main/docs/THREAT_MODEL.md">threat model</a>.</p></div>
  <p>We publish an Agent Leak Benchmark, a set of ways an AI agent can expose a key. Run it yourself with <code>python -m leakbench</code> from the repository.</p>
</div></section>"""

HOW = """<div class="page"><div class="wrap">
  <p class="crumbs"><a href="index.html">StuntKey</a> / How it works</p>
  <h1>How it <em>works</em></h1>
  <p class="lede">The idea is simple. Through the broker, the key does not go where the AI can read it.</p>
  <h2>The stunt double</h2>
  <p>In a film, the stunt double does the risky part. StuntKey does the same for your keys. Your AI gets a stand-in and uses that. StuntKey swaps in the real key only at the last moment, outside the AI's sight.</p>
  <h2>Step by step</h2>
  <ol class="steps">
    <li><b>You save a key once.</b><p>StuntKey locks it in your computer's keychain: Windows Credential Manager, macOS Keychain, or the Linux keyring.</p></li>
    <li><b>Your AI asks for a call.</b><p>It says "call this service", or it talks to a local stand-in address. The key is not in its environment.</p></li>
    <li><b>StuntKey makes the call.</b><p>It adds the real key, sends the request to the right website, and hands back only the answer.</p></li>
    <li><b>StuntKey keeps watch.</b><p>It blocks the sneaky routes: dumping environment variables, reading your private keys, opening your <code>.env</code> file. With the Claude Code hook, a key that appears in a command's output is hidden before the AI reads it.</p></li>
  </ol>
  <h2>You stay in charge</h2>
  <ul class="tick">
    <li>Set a daily limit for each key: <code>stuntkey caps show</code>.</li>
    <li>Stop everything at once: <code>stuntkey stop</code>. Start again with <code>stuntkey resume</code>.</li>
    <li>See what happened: <code>stuntkey audit</code>.</li>
    <li>Find keys already lying around: <code>stuntkey scan</code>.</li>
  </ul>
  <h2>What it does not do</h2>
  <div class="note"><p>It lowers risk, it does not remove it. It cannot stop an AI misusing a key it is allowed to use, and it does not protect against malware already running as you (anything running as you can read your keychain). Other AI apps (Cursor, Codex, Gemini, Claude Desktop) have no hook for their file tools. It is beta and has not had an independent security review.</p></div>
  <div class="ctas"><a class="btn" href="add-your-first-key.html">Add your first key</a></div>
</div></div>"""

FIRST = """<div class="page"><div class="wrap">
  <p class="crumbs"><a href="index.html">StuntKey</a> / Add your first key</p>
  <h1>Add your <em>first key</em></h1>
  <p class="lede">About a minute. You never type a key into a web page, and you never paste it into your AI chat.</p>
  <ol class="steps">
    <li><b>Install StuntKey.</b><p>You need Python 3.10 or newer. In a terminal:</p>
      <div class="cmd"><code>pip install stuntkey</code></div></li>
    <li><b>Check your computer.</b><p>This looks for keys lying around and says what to do next. It changes nothing.</p>
      <div class="cmd"><code>stuntkey start</code></div></li>
    <li><b>Add the key.</b><p>Swap <code>openai</code> for your service. StuntKey opens that service's key page. Click the site's own Copy button. StuntKey takes the key from your copy, tests it, and locks it in your keychain.</p>
      <div class="cmd"><code>stuntkey get openai</code></div></li>
    <li><b>Plug it into your AI tools.</b><p>Shows the change first and asks before it does anything. Run it in your project folder.</p>
      <div class="cmd"><code>stuntkey install</code></div></li>
    <li><b>Check it worked.</b><p>Shows where each key lives and how old it is. Names only, never the key.</p>
      <div class="cmd"><code>stuntkey status</code></div></li>
  </ol>
  <div class="note"><p><b>Want to see it work first?</b> <code>stuntkey try</code> saves a pretend key, uses it, then forgets it, in a throwaway place. No real key is used.</p>
  <p><b>Leaked a key?</b> <code>stuntkey panic openai</code> walks you through cancelling it and making a new one.</p></div>
  <p class="say">Stuck? Email <a href="mailto:office@calasautomations.com">office@calasautomations.com</a>.</p>
</div></div>"""

wr(os.path.join(SITE, "index.html"), page("index.html", "StuntKey by Calas Automations",
   "StuntKey keeps your API keys in your keychain and lets your AI use them through a broker, so the key stays out of its environment. Free, open source.", INDEX))
wr(os.path.join(SITE, "how-it-works.html"), page("how-it-works.html", "How StuntKey works - Calas Automations",
   "How StuntKey keeps your API keys out of your AI's environment, in plain words.", HOW))
wr(os.path.join(SITE, "add-your-first-key.html"), page("add-your-first-key.html", "Add your first key - StuntKey by Calas Automations",
   "Add your first API key to StuntKey in about a minute: install, check, add, connect.", FIRST))

tpl = rd(os.path.join(SRC, "web.tpl.html"))
wr(os.path.join(ROOT, "stuntkey", "web", "index.html"), tpl.replace("/*@@CSS@@*/", css))
if __name__ == "__main__":
    write_all()
    print("built", os.path.join(SITE), "and stuntkey/web/index.html")
