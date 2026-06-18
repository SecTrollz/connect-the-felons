"""
CTF Android Bridge
------------------
This is the file Chaquopy loads first. It sets up sys.path so all
nine modules can find evidence_journal.py regardless of where Chaquopy
extracts them, then exposes a single run_investigation() function that
MainActivity.kt calls. One entry point, zero duplicated logic.
"""
import sys
import os
import json
import io as _io

# Ensure the python/ root is on the path so `from evidence_journal import`
# works from inside modules/ even under Chaquopy's asset extraction layout.
_root = os.path.dirname(os.path.abspath(__file__))
if _root not in sys.path:
    sys.path.insert(0, _root)


def run_investigation(target: str) -> str:
    """
    Called from MainActivity.kt:
        py.getModule("ctf_bridge").callAttr("run_investigation", query)

    Captures all print() output (the narration from each module),
    runs the investigation, and returns a single JSON string with:
      - "log": the narration text
      - "results": the structured findings dict
      - "error": only present if something threw
    """
    from main import Investigation

    buf = _io.StringIO()
    original_stdout = sys.stdout
    sys.stdout = buf

    try:
        inv = Investigation()
        results = inv.run([target])
        log = buf.getvalue()
        return json.dumps({
            "log": log,
            "results": results,
        }, indent=2, default=str)
    except Exception as exc:
        log = buf.getvalue()
        return json.dumps({
            "log": log,
            "error": str(exc),
            "error_type": type(exc).__name__,
        }, indent=2)
    finally:
        sys.stdout = original_stdout
