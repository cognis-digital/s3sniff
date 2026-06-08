"""S3SNIFF — defensive cloud-bucket ACL/policy triage.

Flags risky S3-style bucket ACLs and policies from a listing or policy JSON.
Analysis / triage / detection only. No network access, no mutation, no
attack capability. Pure standard-library.
"""
from .core import (
    Finding,
    Severity,
    analyze_acl,
    analyze_policy,
    analyze_listing,
    analyze_document,
    summarize,
    SEVERITY_ORDER,
)

TOOL_NAME = "s3sniff"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Severity",
    "analyze_acl",
    "analyze_policy",
    "analyze_listing",
    "analyze_document",
    "summarize",
    "SEVERITY_ORDER",
]
