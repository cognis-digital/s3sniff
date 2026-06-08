"""s3sniff — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from s3sniff.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:
    from s3sniff.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "s3sniff"
    TOOL_VERSION = "0.1.0"
__version__ = TOOL_VERSION
