"""Action-attribution: diff a baseline against a post-action log database.

``diff.run_diff(baseline_db, action_db, csv_out, sqlite_out)`` is the pure
operation: given two extracted databases it writes the retained-lines CSV and
the flagged-everything SQLite, returning a ``DiffResult``. ``report`` renders
that result; neither prints.

Driving a full *interactive* identify (baseline → user performs an action →
post-action capture → diff) is deliberately NOT an operation here: the pacing
("wait until the operator has done the action") is frontend policy. Any
frontend drives it by composing the existing ops in this sequence:

    1. acquire(...)                     # baseline (e.g. last N minutes)
    2. <frontend waits however it likes: CLI prompt, GUI button, timer, …>
    3. acquire(...)                     # post-action capture
    4. run_extract(...) on each, then run_diff(baseline_db, action_db, …)

The CLI's interactive driver lives in ``launcher/cmds/identify_cmd.py``; a GUI
would wire the same steps to widgets.
"""
