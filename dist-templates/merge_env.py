#!/usr/bin/env python3
"""Produce a merged .env candidate for `upgrade.sh`.

Reads the operator's live .env and the new version's example.env, then writes a
candidate that keeps the live file verbatim (every value, comment, and blank
line) and appends only the KEY= assignments that are new in this version, each
carried over with the contiguous comment block that precedes it in the example.
The live file is never modified — upgrade.sh writes the result to .env.upgraded
for the operator to review and adopt.

Stdlib only (FEMUR config is flat dotenv, not YAML, so no ruamel is needed).

Usage:
    merge_env.py <live.env> <new_example.env> <output_candidate.env>

Exit codes:
    0  merge written (added keys, if any, printed one per line to stdout)
    2  bad arguments / unreadable input
"""
import sys


def _fail(msg, code):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


def _key_of(line):
    """Return the KEY of a `KEY=value` assignment line, or None.

    Ignores comments and blank lines. Tolerates leading whitespace and an
    optional `export ` prefix.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export "):].lstrip()
    if "=" not in stripped:
        return None
    key = stripped.split("=", 1)[0].strip()
    return key or None


def _existing_keys(text):
    return {k for k in (_key_of(ln) for ln in text.splitlines()) if k}


def main(live_path, example_path, out_path):
    try:
        with open(live_path, encoding="utf-8") as f:
            live_text = f.read()
    except OSError as e:
        _fail(f"ERROR: cannot read live config {live_path}: {e}", 2)
    try:
        with open(example_path, encoding="utf-8") as f:
            example_lines = f.read().splitlines()
    except OSError as e:
        _fail(f"ERROR: cannot read new example {example_path}: {e}", 2)

    have = _existing_keys(live_text)
    added = []
    additions = []  # lines to append (comment block + assignment)
    pending_comments = []  # comment/blank lines seen since the last assignment

    for line in example_lines:
        key = _key_of(line)
        if key is None:
            # Comment or blank — buffer it as a candidate lead-in for the next key.
            pending_comments.append(line)
            continue
        if key not in have:
            additions.extend(pending_comments)
            additions.append(line)
            added.append(key)
        # A key was consumed (added or already present); reset the buffer so its
        # comments don't leak onto an unrelated later addition.
        pending_comments = []

    out_text = live_text
    if additions:
        # Ensure exactly one separating blank line before the appended block.
        if out_text and not out_text.endswith("\n"):
            out_text += "\n"
        out_text += "\n# --- New keys added by upgrade (review and set values) ---\n"
        out_text += "\n".join(additions) + "\n"

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(out_text)
    except OSError as e:
        _fail(f"ERROR: cannot write merged candidate {out_path}: {e}", 2)

    for key in added:
        print(key)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        _fail("usage: merge_env.py <live.env> <new_example.env> "
              "<output_candidate.env>", 2)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
