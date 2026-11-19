"""Output masking of a disguised key, with the key stored the way `stuntkey get` stores it (keychain + fingerprint).

The final review reported that a zero-width character, a soft hyphen, a no-break space, NULs or ANSI codes between the characters of a key
let it through the output mask. That was true only for a key that exists as a fingerprint alone (for example one that lives only in a
.env file). For a key in the keychain every form below is masked; these tests pin that, and one test states the fingerprint-only limit
so it cannot be forgotten."""
import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_codexhook import SECRET, throwaway_home  # noqa: E402

from stuntkey import hook, keychain, scrub  # noqa: E402

DISGUISES = {
    "zero-width space": chr(0x200B).join(SECRET),
    "soft hyphen": chr(0xAD).join(SECRET),
    "no-break space": chr(0xA0).join(SECRET),
    "NUL between": chr(0).join(SECRET),
    "ANSI codes between": "\x1b[0m".join(SECRET),
    "base64 at an offset": base64.b64encode(b"x" + SECRET.encode()).decode(),
    "hex with colons": ":".join("%02x" % b for b in SECRET.encode()),
    "UTF-16 read as text": SECRET.encode("utf-16le").decode("latin-1"),
}


def masked(text):
    out = hook.post_check({"tool_name": "Bash", "tool_input": {"command": "x"},
                           "tool_response": {"stdout": "value: " + text, "stderr": "", "interrupted": False, "isImage": False}})
    return bool(out)


class Disguises(unittest.TestCase):
    def test_a_keychain_key_is_masked_in_every_disguise(self):
        with throwaway_home():
            keychain.store("svc", "API_KEY", SECRET, keychain.detect_backend())
            scrub.remember_key("svc/API_KEY", SECRET)
            self.assertTrue(masked(SECRET), "the plain key")
            for name, text in DISGUISES.items():
                self.assertTrue(masked(text), name)

    def test_a_fingerprint_only_key_covers_the_plain_forms_but_not_every_disguise_a_stated_limit(self):
        with throwaway_home():
            scrub.remember_key("svc/API_KEY", SECRET)            # no keychain entry: the key lives only in a file
            self.assertTrue(masked(SECRET))
            self.assertFalse(masked(DISGUISES["zero-width space"]), "if this starts masking, update the README limit that says it does not")

    def test_ordinary_output_is_not_masked(self):
        with throwaway_home():
            keychain.store("svc", "API_KEY", SECRET, keychain.detect_backend())
            scrub.remember_key("svc/API_KEY", SECRET)
            self.assertFalse(masked("hello world 12345 and a sentence with sk-live words"))


if __name__ == "__main__":
    unittest.main()
