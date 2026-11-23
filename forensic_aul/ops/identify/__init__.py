"""Action-attribution: diff a baseline against a post-action log database.

``diff.run_diff(baseline_db, action_db, csv_out, sqlite_out)`` is the pure
operation: given two extracted databases it writes the retained-lines CSV and
the flagged-everything SQLite, returning a ``DiffResult``. ``report`` renders
that result; neither prints.

The full interactive identify (baseline → the operator performs an action →
post-action capture → extract both → diff) is ``run_identify_workflow``
(workflow.py), configured by ``IdentifyOptions`` (options.py). The pacing ("wait
until the operator has done the action") stays frontend policy: it is injected as
callbacks (``wait_still``, ``wait_for_action``, ``confirm``), so the CLI
(launcher/cmds/identify_cmd.py) and the GUI (gui/controllers/identify.py) drive the
same sequence.
"""
