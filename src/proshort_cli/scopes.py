"""The permissions this CLI knows about.

Its own module because two things need it and neither can import the other:
`cli` builds the `--scope` list from it, and `api` checks the scope a server
names in a `WWW-Authenticate` challenge against it before that value is ever put
in a sentence a person -- or an agent -- might run.
"""

SCOPES: tuple[str, ...] = (
    "profile:read",
    "filters:read",
    "deals:read",
    "reps:read",
    "recordings:read",
    "meetings:read",
)
