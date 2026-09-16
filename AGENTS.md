# Repository guide

Public product repository for `osslscope`. Only public material here.

## Sources of truth

- Start with `README.md`; `CHANGELOG.md` tracks what is in the tree.
- Approved product specs live under `docs/` (see `docs/README.md`
  for the planned layout).

## Working agreements

- Keep changes scoped and preserve unrelated work.
- Never capture secrets: no plaintext, keys, passwords, or application
  payloads. Any future capture allowlist must be preserved, never
  broadened implicitly.
- Linux-first; eBPF uprobes; no application changes, no interposition.
- Scope: execution-backed crypto inventory only. Full NOT-do list: README (What it will NOT do).
- Do not track generated output. Get explicit approval for privileged
  or container experiments.

## History

- Work must live in commits, not in the working tree: dev branches,
  worktrees, and task branches always contain the commits for the work
  done on them — otherwise history is lost.
- Committing finished, verified work is authorized by default, on any branch.
- Rewriting history (amend, rebase, reset) and pushing require explicit
  user agreement.
- Commit messages follow repo style: `<area>: <imperative summary>`
  (`fix: …`, `feat: …`, `refactor: …`, `test: …`, `docs: …`).

## Checks

Stack: Rust + Aya proposed (owner: P0 phase gate). Once confirmed, this section must name the exact gates (format, check, test, lint) with pinned versions.
