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

Stack confirmed at the P0 gate (Rust 1.88.0 + Aya 0.14, raw multi-link
primary). Gates, pinned toolchain (`rust-toolchain.toml`):

- `cargo fmt --check`
- `cargo check --workspace --locked`
- `cargo test --workspace --locked`
- `cargo clippy --workspace --locked -- -D warnings` (from first lint-clean commit)
