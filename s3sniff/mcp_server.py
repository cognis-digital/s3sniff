"""S3SNIFF MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from s3sniff.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-s3sniff[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-s3sniff[mcp]'")
        return 1
    app = FastMCP("s3sniff")

    @app.tool()
    def s3sniff_scan(target: str) -> str:
        """Flag risky cloud-bucket ACLs/policies from a listing or policy JSON. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
