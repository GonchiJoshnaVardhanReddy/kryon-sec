"""Kryonsec package identity."""

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("kryonsec")
except PackageNotFoundError:  # source tree before an editable install
    __version__ = "1.3.11"
