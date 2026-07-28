# Workflows

Three end-to-end procedures, each answering a different question.

| Workflow | Question | Read it when |
|---|---|---|
| [Case workflow](case-workflow.md) | *What is on this device, and can I defend how I got it?* | You are processing evidence: acquire or receive → extract → summary → annotate → export → verify-hash, with the chain-of-custody hygiene that goes with each step. |
| [Identify an action](identify-action.md) | *Which log lines does this device write when a user does X?* | You are researching behaviour on a test device: baseline → action → post capture → diff → review and prune → export. The raw material for knowledge-base signatures. |
| [Validation](validation.md) | *Is the tool telling the truth?* | You need to demonstrate that the parser agrees with Apple's own `log show`, and that our acquisition matches Apple's `log collect` — the L1 / L2 / L3 self-check layers. |

The first is the day job. The second builds the knowledge that makes the first
useful. The third is what you show when the method itself is questioned.

Each workflow is written CLI-first; the library equivalents live in
[../library/recipes.md](../library/recipes.md) and the GUI mirrors the same steps
in [../gui.md](../gui.md).

## See also

- [../getting-started.md](../getting-started.md) — install and first run
- [../cli/index.md](../cli/index.md) — full command reference
- [../concepts/forensic-model.md](../concepts/forensic-model.md) — why the ordering,
  hashing and integrity choices are what they are
