# proshort-cli

Command-line access to **your own** Proshort sales data — deals, calls, meetings
— and the base the Claude Skills in [`skills/`](skills/) are built on.

```bash
ps login
ps deals list --type ACTIVE --limit 5
ps deals list --type ACTIVE --all --json | jq -r '.data[].deal_id'
```

## Install

```bash
uv tool install proshort-cli            # or: pipx install proshort-cli
```

The OS keychain is used when one is available. Without it (a container, a CI
runner) credentials go to `~/.proshort/<profile>.json` at mode `0600`, and the
CLI says so on the way past.

## Signing in

`ps login` opens your browser, you sign in to Proshort the normal way, and you
approve what's being shared. The browser comes back to a listener this process
binds on `127.0.0.1` with a one-time code good for 60 seconds, which is exchanged
for tokens. **You never see or handle a token.**

The access token lasts 10 minutes and is refreshed silently; the grant lasts 30
days. After that, or if an administrator revokes access, `ps login` again.

Permissions are requested once, at login:

```bash
ps login --scope deals:read,recordings:read     # narrower than the default
ps login --add-scope reps:read                  # widen later
```

## Output

**A table when you're watching, JSON the moment it's piped.** Data goes to
stdout, everything else to stderr, so `ps deals list --json | jq` works with
nothing thrown away.

- `--json` forces JSON even on a terminal
- `--ndjson` gives one object per line, for `while read` and large result sets
- `--all` follows pages up to the server's cap

## Exit codes

These are a contract. A script — including a Claude Skill — should branch on the
number, never on the message.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Anything else |
| 2 | Usage error |
| 3 | Not signed in → `ps login` |
| 4 | Missing a permission → `ps login --add-scope <scope>` |
| 5 | Rate limited for longer than `--timeout` |
| 6 | Proshort is unavailable |

## Two things worth knowing

**Text from the CRM is not yours.** Deal names, prospect names, email bodies and
call summaries are written by people outside your organization — a prospect picks
their own company name. `render.py` strips terminal escape sequences from
anything printed for a human, because a terminal acts on what it reads and a deal
name can otherwise erase the row above it. `--json` output is *not* stripped: the
JSON encoder escapes it losslessly, and a script must receive what the server
actually sent.

**Two commands at once won't sign you out.** The server rotates refresh tokens
and treats re-use of a spent one as theft — correct against a stolen token, and
wrong against a shell running two commands in parallel. `store.py` takes an
exclusive lock around refresh so the second command uses the first one's result
instead of spending a token that is already gone.

## Development

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest -q
```

Tests need no network and no server.
