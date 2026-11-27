# The ledger of the Giant Swarm line of containerd

One file per change the line carries on top of the pin (`git log <pin>..giantswarm`, without the fork's own
infrastructure, which `FORK.md` describes): `fork/<slug>.md`, added in the same pull request as the change, so two
concurrent pull requests never edit the same lines. The directory is the index; `FORK.md` carries no per-change rows.

```markdown
---
id: <the file name without .md>
fork: containerd
category: bugfix | feature | compat | test | gs-specific
status: carried | dropped | superseded
commits:
  - '<the subject of each carried commit, as git shows it>'
upstream:
  outcome: merged | open | declined | superseded | to-file | fork-only | drops-at-repin | none
  refs: [containerd/containerd#N, ...]
  branch: upstream/<slug>
  exit: <what makes the change leave the line, e.g. the first containerd release that contains it>
verified: <YYYY-MM-DD, the day the upstream state was last checked>
---
# <short title>

## Change

What the commit does.

## Reason

Why the line carries it.

## History

What upstream and the line did about it, by date; prose, not state.
```

A change prepared for upstream and not yet opened there reads `outcome: to-file` and, in its History, "to file —
prepared in the fork: branch `upstream/<slug>`" (FORK.md, "Contributing").
