# leaseguard

Approval leases for agent-run commands — approvals that expire by construction.

## The problem

You run a coding agent. It asks: *"can I run `npm run deploy`?"* You glance at the diff, say yes, go back to your coffee. The agent runs it **40 minutes later**, from a different directory, against code that changed twice since you approved.

You approved the command at 10:00. You did not approve the command at 10:40. But nobody wrote that down, so the approval quietly survived past its own relevance. This is the "stale approval" problem in agentic workflows: a yes with no expiry date, no scope, and no receipt.

## The fix

`leaseguard` turns your "yes" into a **lease**: signed, time-boxed, directory-scoped, and logged.

```sh
# you (the human) grant a 10-minute lease for the deploy command, in this directory
leaseguard grant "npm run deploy" --for 10m --note "hotfix for #42"
# lease 9f2c1ab4e011 granted
#   valid   : 10m (until 2026-10-20T12:25:00.000Z)
#   scope   : /home/you/myapp
#   token   : eyJ2IjoxLCJpZCI6...

# the agent runs everything through the gate
leaseguard run --lease <token> -- npm run deploy
```

The gate checks, in order: the standing **deny policy** (deny always wins, even over a valid lease) → the lease signature → expiry → directory scope → command pattern. Then it runs the command, passes through its exit code, and appends the decision to a **hash-chained ledger**. `leaseguard audit` shows you what ran, what was denied, which approvals died quietly unused, and whether anyone tampered with the log.

Demo (real output, from `examples/demo.sh` — a 3-second lease, used once, then expired):

```
### 1. grant a 3-second lease for the deploy command
lease <id> granted
  pattern : echo deploy-*
  valid   : 3s (until <ts>)
  scope   : <tmpdir>
  note    : demo lease
  token   : <token>

run it with: leaseguard run --lease <token> -- echo deploy-<arg>

### 2. run it right away -> allowed
deploy-backend

### 3. run it again after the lease expired -> denied
leaseguard: denied: lease <id> expired at <ts> — ask for a fresh approval

### 4. audit: the stale approval died quietly, nothing ran on it
leaseguard audit
  leases : 1 total — 0 active, 0 revoked, 1 expired (used), 0 expired unused
  runs   : 1 allowed, 1 denied
  ledger : 3 entries, hash chain OK

  recent denials:
    [<ts>] lease-expired: echo deploy-backend
```

## Install (3 steps)

No dependencies. Node 18+.

```sh
git clone https://github.com/techdevfun/leaseguard.git
cd leaseguard
npm link   # or: chmod +x leaseguard.js && ln -s $PWD/leaseguard.js ~/.local/bin/leaseguard
```

Verify it works:

```sh
leaseguard help
npm test   # 18 tests, ~5 seconds
```

## Usage

**Grant a lease** — pattern is a glob matched against the full command string:

```sh
leaseguard grant "npm run deploy" --for 10m              # default scope: current dir
leaseguard grant "kubectl rollout restart *" --for 2m --scope ./infra --note "incident #7"
leaseguard grant "rm -rf ./dist" --for 30s
```

Durations: `30s`, `10m`, `2h`, `1d` (default `15m`).

**Run through the gate** — the agent's wrapper. Exit codes: `0` ran (command's own code passes through), `2` denied (no lease / no policy allow), `3` bad or expired lease, `4` policy deny:

```sh
leaseguard run --lease $TOKEN -- npm run deploy
leaseguard run --lease-file ./lease.token -- npm run deploy   # avoid the token in `ps`
LEASEGUARD_LEASE=$TOKEN leaseguard run -- npm run deploy      # or via env var
```

Commands run **directly, no shell** — the exact approved argv is what executes. Need pipes? Run `sh -c` explicitly and make the pattern match the full `sh -c "..."` string.

**Standing policy** — always-on allow/deny globs, no lease needed for the boring stuff. Deny always wins:

```json
{ "allow": ["npm test", "git status"], "deny": ["rm -rf *", "curl * | sh", "git push * --force"] }
```

```sh
leaseguard run --policy examples/policy.json -- npm test
```

**Manage & audit:**

```sh
leaseguard leases          # active / expired / revoked
leaseguard revoke 9f2c1a   # kill a lease now (prefix match ok; an ambiguous prefix is refused, not guessed)
leaseguard audit           # summary + tamper check of the ledger
leaseguard audit --json    # machine-readable
```

Everything lives in `~/.leaseguard/` (`key`, `leases.json`, `ledger.jsonl`); point it elsewhere with `LEASEGUARD_HOME`.

## What this does NOT do (honest limits)

- It does **not** stop a determined adversary with your file permissions. Anyone who can read `~/.leaseguard/key` can mint leases. Run the grant side from your shell or your CI — not from the agent.
- The token on a command line is visible in `ps`; use `--lease-file` or the env var for real use.
- It checks *what was approved and when* — it does not judge whether the command itself is wise. A lease for `rm -rf *` is still your fault.

## Roadmap

- `--approve-once` leases (single use, then auto-revoke)
- `leaseguard watch` — tail the ledger live during an agent session
- Optional agent-side hook examples (Claude Code / Codex pre-tool hooks)

## License

MIT — see [LICENSE](LICENSE).
