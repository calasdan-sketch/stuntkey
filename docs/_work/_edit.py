"""tiny helper: python _edit.py FILE  (reads pairs from _edits.json) - newline-safe replace"""
import json, sys, io
path = sys.argv[1]
pairs = json.load(open(sys.argv[2], encoding="utf-8"))
raw = open(path, "rb").read().decode("utf-8")
crlf = "\r\n" in raw
text = raw.replace("\r\n", "\n")
for old, new in pairs:
    if text.count(old) != 1:
        print("NOMATCH(%d): %r" % (text.count(old), old[:70])); sys.exit(1)
    text = text.replace(old, new)
if crlf:
    text = text.replace("\n", "\r\n")
open(path, "wb").write(text.encode("utf-8"))
print("ok", path, "crlf" if crlf else "lf")
