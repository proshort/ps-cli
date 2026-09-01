"""Command-line access to your own Proshort sales data."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Read from the installed metadata rather than repeated here, so the two
    # cannot drift. `pyproject.toml` is the single source.
    __version__ = version("proshort-cli")
except PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0+source"
