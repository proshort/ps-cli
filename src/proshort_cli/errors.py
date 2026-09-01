"""Exit codes, and the failures behind them.

These are a contract, not diagnostics. A Claude Skill's script has to tell "sign
in again" from "Proshort is down" *without reading English*, because the sentence
it would parse is the thing most likely to be reworded later. So the number is
the interface and the message is for the human.

    0  success
    1  anything else
    2  usage error
    3  not authenticated              -> run `ps login`
    4  insufficient scope             -> run `ps login --add-scope <scope>`
    5  rate limited beyond --timeout
    6  Proshort is unavailable
"""

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_SCOPE = 4
EXIT_RATE_LIMIT = 5
EXIT_UNAVAILABLE = 6


class CliError(Exception):
    """A failure with a decided exit code."""

    def __init__(self, message: str, code: int = EXIT_ERROR, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.hint = hint


class NotAuthenticated(CliError):
    def __init__(self, message: str = "Not signed in.") -> None:
        super().__init__(message, EXIT_AUTH, hint="Run: ps login")


class InsufficientScope(CliError):
    def __init__(self, scope: str | None) -> None:
        hint = f"Run: ps login --add-scope {scope}" if scope else "Run: ps login"
        super().__init__(
            f"This session was not granted {scope}." if scope else "Missing a required permission.",
            EXIT_SCOPE,
            hint=hint,
        )


class RateLimited(CliError):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            f"Rate limited, and the wait ({retry_after}s) is longer than --timeout.",
            EXIT_RATE_LIMIT,
            hint="Raise --timeout, or slow the loop down.",
        )


class Unavailable(CliError):
    # No hint: the server's own message already says to retry, and printing a
    # second line that repeats it reads as two separate pieces of advice.
    def __init__(self, message: str = "Proshort is unavailable. Try again shortly.") -> None:
        super().__init__(message, EXIT_UNAVAILABLE)
