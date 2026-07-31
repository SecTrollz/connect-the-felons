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


def run_investigation(target: str, storage_dir: str = None,
                       github_token: str = None, hibp_key: str = None) -> str:
    """
    Called from MainActivity.kt:
        py.getModule("ctf_bridge").callAttr(
            "run_investigation", query, filesDir.absolutePath, ghToken, hibpKey)

    storage_dir should be the app's writable private storage
    (context.filesDir.absolutePath on Android). Chaquopy's process cwd is
    not writable, so without this every EvidenceJournal write fails and
    the investigation dies before it produces anything. On desktop/Termux
    this can be left None and the journal falls back to a cwd-relative
    default.

    Captures all print() output (the narration from each module),
    runs the investigation, and returns a single JSON string with:
      - "log": the narration text
      - "results": the structured findings dict
      - "error": only present if something threw
    """
    from main import Investigation
    from report_engine import ReportEngine

    base_dir = None
    reports_dir = None
    if storage_dir:
        base_dir = os.path.join(storage_dir, "investigations", "evidence_chains")
        reports_dir = os.path.join(storage_dir, "investigations", "reports")

    buf = _io.StringIO()
    original_stdout = sys.stdout
    sys.stdout = buf

    try:
        inv = Investigation(base_dir=base_dir, github_token=github_token, hibp_key=hibp_key)
        results = inv.run([target])

        # Report Engine: turn what was just found into the
        # law-enforcement handoff and court-admissible report. Both are
        # generated every run rather than gated behind a separate call -
        # simplest way to make them reachable from the one RUN button.
        engine = ReportEngine(inv.journal, output_dir=reports_dir)
        le_report = engine.le_handoff(findings_summary={
            "key_findings": inv._collect_findings(),
            "red_flags": inv._collect_flags(),
        })
        court_report = engine.court_report()

        log = buf.getvalue()
        return json.dumps({
            "log": log,
            "results": results,
            "le_report": le_report,
            "court_report": court_report,
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


# Module 9's RF sweep and persistence audit depend on termux-api binaries
# (termux-wifi-scaninfo, termux-telephony-cellinfo, termux-sensor),
# optionally rtl_power, and/or `adb`/`pm`/`dumpsys` shell access - none of
# which exist inside the packaged app's Chaquopy sandbox. Same reason
# Module 5's ADB device analysis was never wired into this bridge: they
# only do anything useful run directly under Termux, so they stay CLI-only
# (`python main.py --rf-scan` / `--persistence-scan`), not app buttons that
# would just report "unavailable" every time.
