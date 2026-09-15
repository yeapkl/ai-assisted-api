# API Dev Team — Subagent Pipeline

Five isolated agents, one per role: `ba`, `developer`, `qa`, `pentester`,
`reviewer`. Each is a plain markdown file in this folder — commit them and
they're available in every future Claude Code session opened against this
repo, for you or anyone on the team. No server, no registration step.

## Why these are "isolated" and not just role-play

Each invocation spins up a fresh subagent with **only that file's
instructions and whatever you explicitly hand it in the prompt** — it does
not see the parent conversation's history or another agent's internal
reasoning, only the artifacts (docs, code, running service) passed between
them. That's what makes qa's pass and the pentester's findings an actual
independent check rather than the same train of thought re-labeled.

## How to run it

From a Claude Code session in this repo, either:
- Ask Claude directly: "use the ba agent to draft requirements for X,
  then have the developer build it, then qa, then pentester, then
  reviewer" — Claude will invoke each via the Agent/Task tool in sequence,
  passing the previous stage's output forward.
- Or invoke a single stage directly if you're re-running just one step,
  e.g. "have the pentester agent test the /auth endpoints again."

## The handoff chain

```
business ask
   │
   ▼
 ba          → docs/requirements/<slug>.md
   │
   ▼
 developer   → code + a handoff note (how to run it)
   │
   ▼
 qa          → docs/qa/<slug>-report.md          (PASS/FAIL)
   │  (only proceeds past here if PASS)
   ▼
 pentester   → docs/pentest/<slug>-report.md      (findings + verdict)
   │
   ▼
 reviewer    → docs/review/<slug>-review.md       (APPROVED / CHANGES REQUIRED)
```

If qa or pentester or reviewer sends something back, the loop is: developer
fixes → re-run the stage that failed (not necessarily the whole chain from
the top) → continue.

## Adding/editing an agent

Edit the relevant `.md` file directly — frontmatter controls `tools` (what
it's allowed to touch; e.g. pentester deliberately has no `Edit`/`Write` to
source) and `model`. Commit the change; it takes effect on the next
invocation, no reload step needed.
