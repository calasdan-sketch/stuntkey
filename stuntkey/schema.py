"""Versioned files: one way to say "this file is in another format".

StuntKey keeps a few small files of its own (the consent list, the key-dates
file, the recipe approvals, the project manifest). Each says which format it
is in. This module is the one place that decides what to do when that format
is not the one this StuntKey writes:

  - the same format        -> used as it is
  - an OLDER format        -> brought forward in memory by the steps in
                              `migrations` ({old_version: fn(doc) -> doc for
                              old_version + 1}); the caller writes the new
                              format on its next save
  - a NEWER format         -> never guessed at and never overwritten: a plain
                              message says to update StuntKey
  - an older format with no step on hand -> the same, in other words

It imports nothing from stuntkey (a leaf, like logfacts), so any module may
use it without making an import cycle. store.migrate_document is the older
name for load_versioned and now calls it.
"""
from __future__ import annotations

DEFAULT_HINT = "pipx upgrade stuntkey"


class SchemaError(OSError):
    """A saved file's format cannot be used by this StuntKey. str() is plain
    words saying why and what to do. `kind` is "newer", "old" or "invalid"."""

    def __init__(self, message: str, path: str | None = None, kind: str = "invalid"):
        super().__init__(22, message, path)
        self.plain = message
        self.kind = kind

    def __str__(self) -> str:
        return self.plain


def version_of(doc: dict, key: str = "schema_version", alt: str = "version") -> int:
    """The format a document says it is in: `key`, else `alt`, else 1. Anything
    that is not a whole number of at least 1 counts as 1 (the first format)."""
    raw = doc.get(key, doc.get(alt, 1))
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 1 else 1


def load_versioned(doc: dict, current: int, migrations: dict, what: str,
                   path: str | None = None, update_hint: str = DEFAULT_HINT) -> dict:
    """`doc` in format `current`, or a SchemaError with plain words.

    `what` names the file for the person ("The consent list"). The document's
    own "schema_version" (or the older name "version") says its format; none
    means 1. Each step in `migrations` gets the document and returns it in the
    next format; this function then sets the version field(s) itself."""
    if not isinstance(doc, dict):
        raise SchemaError(f"{what} is not in a form this StuntKey can read.", path)
    version = version_of(doc)
    if version > current:
        raise SchemaError(
            f"{what} was made by a newer StuntKey (its format is {version}; this "
            f"one reads up to {current}). Update StuntKey ({update_hint}) and try "
            "again. The file was left as it is.", path, "newer")
    doc = dict(doc)
    while version < current:
        step = migrations.get(version)
        if step is None:
            raise SchemaError(
                f"{what} is in an old format ({version}) that this StuntKey has no "
                f"way to bring forward. Update StuntKey ({update_hint}), or move the "
                "file aside and let StuntKey make a fresh one. The file was left "
                "as it is.", path, "old")
        doc = dict(step(doc))
        version += 1
        doc["version"] = version
        if "schema_version" in doc:
            doc["schema_version"] = version
    return doc
