# proshort-cli

Command-line access to **your own** Proshort sales data — deals, calls, meetings
— and the base the Claude Skills in [`skills/`](skills/) are built on.

```bash
proshort login --url https://<your-proshort-host>
proshort deals list --type ACTIVE --limit 5
proshort deals list --type ACTIVE --all --json | jq -r '.data[].deal_id'
```

## Install

```bash
uv tool install git+https://github.com/proshort/ps-cli
# or: pipx install git+https://github.com/proshort/ps-cli
```

**Not on PyPI, and deliberately not yet.** `pyproject.toml` carries
`Private :: Do Not Upload` and `UNLICENSED`, so `uv tool install proshort-cli`
resolves to nothing. Install from the repository until distribution is decided;
the name is reserved by nobody and the line above is the one that works today.

Running from a clone rather than an install is fine, but `proshort --version`
reads the *installed* package metadata and will report `0.0.0+source`. Use
`uv pip install -e .` in the clone if you need the real number.

**The Skill does not come with the install.** `uv tool install` ships the
`proshort_cli` package and nothing else, so [`skills/`](skills/) has to be copied
separately into wherever Claude Code reads skills from:

```bash
curl -fsSL https://raw.githubusercontent.com/proshort/ps-cli/main/skills/proshort-pipeline-review/SKILL.md \
  -o ~/.claude/skills/proshort-pipeline-review/SKILL.md
```

It is deliberately a copy rather than package data: a Skill is something you read
and edit for your own pipeline, not a file buried in `site-packages`.

**macOS and Linux only in 0.1.0.** The refresh lock uses `fcntl`, so importing
this on Windows fails. A port needs `msvcrt.locking` behind the same interface -
not a large change, just not this one.

The command is `proshort`. There is deliberately no `ps` alias: it would shadow
the POSIX process tool on `PATH`, and `ps aux` quietly becoming this program is a
memorably bad afternoon.

Credentials go to the OS keychain - `keyring` is a hard dependency, not an extra,
so the sentence above is true of a default install. On a machine with no keyring
backend (a container, a CI runner) they fall back to
`~/.proshort/<profile>.json` at mode `0600`, and `login` says so.

## Your first five minutes

```bash
# 1. Install. `proshort` lands on your PATH.
uv tool install git+https://github.com/proshort/ps-cli

# 2. Sign in. Opens your browser; you approve what is shared.
proshort login --url https://<your-proshort-host>

# 3. Check it worked.
proshort whoami
```

`whoami` prints who the session belongs to and which permissions it holds. If it
says `Not signed in`, step 2 did not finish.

Then the thing most people actually want:

```bash
proshort deals list --type ACTIVE --limit 10
```

Ask your Proshort administrator for the host in step 2 — there is deliberately no
default, because a wrong one fails as "Proshort is unavailable", which is true of
nothing and impossible to diagnose from the outside. You pass it once; it is
remembered per profile.

Ids flow between commands, which is most of how you use this:

```bash
id=$(proshort deals list --limit 1 --json | jq -r '.data[0].id')
proshort deals get "$id" --json          # everything known about that deal
proshort activities --deal "$id" --json  # its timeline
```

## Commands

Ten, one per endpoint. Every one is read-only — there is nothing here that writes
to Proshort.

| Command | What it gives you |
| --- | --- |
| `proshort login` | Sign in through the browser |
| `proshort logout` | Revoke the session server-side, then forget it |
| `proshort whoami` | Who this session is, and what it may read |
| `proshort filters` | Filter values you are allowed to filter by |
| `proshort deals list` | Deals from the CRM pipeline |
| `proshort deals get <deal_id>` | Everything known about one deal |
| `proshort activities --deal <id>` | Activity timeline, up to 25 deals at once |
| `proshort reps --duration <window>` | Aggregated per-rep performance |
| `proshort recordings` | Your call recordings (`--shared` for others') |
| `proshort calls <document_id>...` | AI summaries of recorded calls |
| `proshort meetings` | Your upcoming meetings |

Per-command flags are in `proshort <command> --help`. The ones that apply
everywhere: `--json`, `--ndjson`, `--profile`, `--timeout`, `--verbose`.

Worth knowing up front:

- **`--limit` is the page size, not a total.** `--all --limit 10` fetches every
  page, ten rows at a time.
- **`--all` exists only on `deals list` and `recordings`** — the two endpoints
  that page.
- **`--duration` takes one of eight fixed windows**, listed in
  `proshort reps --help`. It is not something `proshort filters` supplies.
- **`--profile`** keeps separate sessions side by side, which is how you hold a
  staging and a production login at once.

## Signing in

There is no default API address: pass `--url` once, or set `PROSHORT_URL`. It is
remembered per profile afterwards. (The previous default was an internal
hostname a customer's machine cannot resolve, which failed as "Proshort is
unavailable" - true of nothing, and the hardest possible thing to diagnose.)

`proshort login` opens your browser, you sign in to Proshort the normal way, and you
approve what's being shared. The browser comes back to a listener this process
binds on `127.0.0.1` with a one-time code good for 60 seconds, which is exchanged
for tokens. **You never see or handle a token.**

The access token lasts 10 minutes and is refreshed silently; the grant lasts 30
days. After that, or if an administrator revokes access, sign in again.

`proshort logout` revokes the grant server-side (RFC 7009) and *then* forgets it
locally, so a copied credential file stops working too. If the server cannot be
reached it still clears locally and tells you it could not revoke.

Permissions are requested once, at login. Passing both of these at once is
refused rather than one being silently dropped:

```bash
proshort login --scope deals:read,recordings:read   # narrower than the default
proshort login --add-scope reps:read                # widen later
```

## Output

**A table when you're watching, JSON the moment it's piped.** Data goes to
stdout, everything else to stderr, so `proshort deals list --json | jq` works
with nothing thrown away.

- `--json` forces JSON even on a terminal
- `--ndjson` gives one object per line, for `while read` and large result sets
- `--all` follows pages until a short page ends the walk, and exists only on
  `deals list` and `recordings` — the two endpoints that page. **It never returns
  a partial result quietly**: any error mid-scan fails the whole command, because
  a short list that looks complete is worse than a visible failure. It also stops
  at a page ceiling rather than following a server that never ends
- `--timeout` is a budget for the **whole command**, waits included, not for each
  request — so `--all` over many pages cannot quietly spend a multiple of it
- Redirecting to a file is a pipe, so `proshort deals list > out.txt` writes JSON,
  not the table. That is the rule working as intended; pass `--json` explicitly if
  you want it to be obvious in the command

## Exit codes

These are a contract. A script — including a Claude Skill — should branch on the
number, never on the message.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Anything else |
| 2 | Usage error |
| 3 | Not signed in -> `proshort login` |
| 4 | Missing a permission -> `proshort login --add-scope <scope>` |
| 5 | Rate limited for longer than `--timeout` |
| 6 | Proshort is unavailable |

## Two things worth knowing

**Text from the CRM is not yours.** Deal names, prospect names, email bodies and
call summaries are written by people outside your organization — a prospect picks
their own company name. `render.py` strips terminal escape sequences from
anything printed for a human, because a terminal acts on what it reads and a deal
name can otherwise erase the row above it. Anywhere the output is one line per
record - table cells, and every diagnostic - newlines and tabs go too, since a
name containing one can otherwise forge a whole extra row that the reader has no
way to spot. `--json` output is *not* stripped: the JSON encoder escapes it
losslessly, and a script must receive what the server actually sent.

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
