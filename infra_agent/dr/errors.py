"""The one exception type the DR package raises for expected failures.

Anything that reaches a caller carries a message that is safe to log and to
show the owner: no credentials, no connection strings, no bundle contents.
"""

from __future__ import annotations


class DRError(RuntimeError):
    pass
