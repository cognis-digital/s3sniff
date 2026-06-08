"""Core triage engine for S3SNIFF.

Consumes S3-style ACL grants and bucket policy documents (the shape returned
by `aws s3api get-bucket-acl` / `get-bucket-policy`) plus simple bucket
listings, and emits structured risk findings. Detection only.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# AWS canonical group URIs that mean "anyone".
_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# Permissions that are write-equivalent and therefore especially dangerous
# when granted to a public/any-authenticated principal.
_WRITE_PERMS = {"WRITE", "WRITE_ACP", "FULL_CONTROL"}
_READ_PERMS = {"READ", "READ_ACP"}


@dataclass
class Finding:
    rule_id: str
    severity: str
    bucket: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _grantee_label(grantee: dict[str, Any]) -> str:
    uri = grantee.get("URI")
    if uri == _ALL_USERS:
        return "AllUsers (public/anonymous)"
    if uri == _AUTH_USERS:
        return "AuthenticatedUsers (any AWS account)"
    return (
        grantee.get("DisplayName")
        or grantee.get("ID")
        or grantee.get("URI")
        or grantee.get("Type", "Unknown")
    )


def analyze_acl(bucket: str, acl: dict[str, Any]) -> list[Finding]:
    """Analyze an S3 ACL document (get-bucket-acl shape)."""
    findings: list[Finding] = []
    grants = acl.get("Grants") or []
    if not isinstance(grants, list):
        return findings

    for grant in grants:
        if not isinstance(grant, dict):
            continue
        grantee = grant.get("Grantee") or {}
        perm = str(grant.get("Permission", "")).upper()
        uri = grantee.get("URI")
        label = _grantee_label(grantee)

        if uri == _ALL_USERS:
            if perm in _WRITE_PERMS:
                findings.append(Finding(
                    rule_id="ACL_PUBLIC_WRITE",
                    severity=Severity.CRITICAL,
                    bucket=bucket,
                    title="Public write/full-control ACL grant",
                    detail=f"Anonymous principal granted {perm}.",
                    evidence={"grantee": label, "permission": perm},
                    recommendation=(
                        "Remove the AllUsers grant; enable S3 Block Public "
                        "Access at the account and bucket level."
                    ),
                ))
            elif perm in _READ_PERMS:
                findings.append(Finding(
                    rule_id="ACL_PUBLIC_READ",
                    severity=Severity.HIGH,
                    bucket=bucket,
                    title="Public read ACL grant",
                    detail=f"Anonymous principal granted {perm}.",
                    evidence={"grantee": label, "permission": perm},
                    recommendation=(
                        "Remove the AllUsers grant unless the bucket is an "
                        "intentional public asset host."
                    ),
                ))
        elif uri == _AUTH_USERS:
            sev = Severity.HIGH if perm in _WRITE_PERMS else Severity.MEDIUM
            findings.append(Finding(
                rule_id="ACL_AUTHUSERS_GRANT",
                severity=sev,
                bucket=bucket,
                title="AuthenticatedUsers ACL grant",
                detail=(
                    f"{perm} granted to any authenticated AWS account "
                    "(not just yours)."
                ),
                evidence={"grantee": label, "permission": perm},
                recommendation=(
                    "AuthenticatedUsers is effectively public to all AWS "
                    "customers; scope to specific principals instead."
                ),
            ))
    return findings


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _principal_is_public(principal: Any) -> bool:
    """True if a policy Principal allows anyone."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for val in principal.values():
            for item in _as_list(val):
                if item == "*":
                    return True
    return False


def _has_condition(statement: dict[str, Any]) -> bool:
    cond = statement.get("Condition")
    return isinstance(cond, dict) and len(cond) > 0


def analyze_policy(bucket: str, policy: dict[str, Any]) -> list[Finding]:
    """Analyze an S3 bucket policy document."""
    findings: list[Finding] = []
    statements = _as_list(policy.get("Statement"))

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        if not _principal_is_public(stmt.get("Principal")):
            continue

        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        sid = stmt.get("Sid") or f"stmt[{idx}]"
        conditioned = _has_condition(stmt)

        wildcard_action = any(a == "*" or a == "s3:*" for a in actions)
        write_action = any(
            a == "*"
            or a == "s3:*"
            or a.lower().startswith("s3:put")
            or a.lower().startswith("s3:delete")
            or "PutObjectAcl".lower() in a.lower()
            for a in actions
        )
        read_action = any(
            a == "*"
            or a == "s3:*"
            or a.lower().startswith("s3:get")
            or a.lower().startswith("s3:list")
            for a in actions
        )

        if wildcard_action:
            findings.append(Finding(
                rule_id="POLICY_PUBLIC_WILDCARD_ACTION",
                severity=Severity.CRITICAL,
                bucket=bucket,
                title="Public statement grants wildcard action",
                detail=(
                    f"Statement '{sid}' allows Principal '*' to perform "
                    f"a wildcard action ({', '.join(actions)})."
                ),
                evidence={"sid": sid, "actions": actions,
                          "conditioned": conditioned},
                recommendation=(
                    "Never pair Principal '*' with wildcard actions; "
                    "enumerate the minimal actions required."
                ),
            ))
        elif write_action:
            findings.append(Finding(
                rule_id="POLICY_PUBLIC_WRITE",
                severity=Severity.CRITICAL if not conditioned else Severity.HIGH,
                bucket=bucket,
                title="Public write/delete policy statement",
                detail=(
                    f"Statement '{sid}' allows Principal '*' to mutate "
                    f"objects ({', '.join(actions)})."
                ),
                evidence={"sid": sid, "actions": actions,
                          "conditioned": conditioned},
                recommendation=(
                    "Remove public write/delete; restrict to specific "
                    "principals and add explicit conditions."
                ),
            ))
        elif read_action:
            findings.append(Finding(
                rule_id="POLICY_PUBLIC_READ",
                severity=Severity.MEDIUM if conditioned else Severity.HIGH,
                bucket=bucket,
                title="Public read policy statement",
                detail=(
                    f"Statement '{sid}' allows Principal '*' to read "
                    f"objects ({', '.join(actions)})."
                    + (" (gated by a Condition)" if conditioned else "")
                ),
                evidence={"sid": sid, "actions": actions,
                          "conditioned": conditioned},
                recommendation=(
                    "Confirm public read is intentional; otherwise scope "
                    "the principal and enable Block Public Access."
                ),
            ))
        else:
            findings.append(Finding(
                rule_id="POLICY_PUBLIC_PRINCIPAL",
                severity=Severity.LOW,
                bucket=bucket,
                title="Public principal on an Allow statement",
                detail=(
                    f"Statement '{sid}' allows Principal '*' for "
                    f"actions {', '.join(actions) or '(none listed)'}."
                ),
                evidence={"sid": sid, "actions": actions,
                          "conditioned": conditioned},
                recommendation="Review whether a public principal is needed.",
            ))

        if not conditioned and stmt.get("Principal") == "*":
            # informational reinforcement, only when no condition present
            pass

    return findings


def analyze_listing(bucket: str, listing: dict[str, Any]) -> list[Finding]:
    """Analyze a bucket listing snapshot for exposure signals.

    Expects a dict with optional keys: 'public' (bool), 'objects' (list of
    {key,size,...}). This models the triage signal that a bucket
    enumerated successfully / is browsable.
    """
    findings: list[Finding] = []
    objects = listing.get("objects")
    if listing.get("public") is True:
        n = len(objects) if isinstance(objects, list) else "unknown"
        findings.append(Finding(
            rule_id="LISTING_PUBLIC_ENUMERABLE",
            severity=Severity.HIGH,
            bucket=bucket,
            title="Bucket contents are publicly enumerable",
            detail=f"Listing succeeded anonymously; {n} object(s) visible.",
            evidence={"object_count": n},
            recommendation=(
                "Disable public list access (s3:ListBucket) and enable "
                "Block Public Access."
            ),
        ))

    # Sensitive object-name heuristics (detection only).
    sensitive_tokens = (
        ".env", ".pem", ".key", "id_rsa", "credentials", "secret",
        ".sql", ".bak", "backup", ".pfx", ".p12", "dump",
    )
    if isinstance(objects, list):
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            key = str(obj.get("key", ""))
            low = key.lower()
            hit = next((t for t in sensitive_tokens if t in low), None)
            if hit:
                findings.append(Finding(
                    rule_id="LISTING_SENSITIVE_OBJECT",
                    severity=Severity.MEDIUM,
                    bucket=bucket,
                    title="Sensitively-named object exposed in listing",
                    detail=(
                        f"Object key '{key}' matches sensitive token "
                        f"'{hit}'."
                    ),
                    evidence={"key": key, "token": hit},
                    recommendation=(
                        "Verify this object should be in a public/listable "
                        "bucket; rotate any exposed secrets."
                    ),
                ))
    return findings


def analyze_document(doc: dict[str, Any]) -> list[Finding]:
    """Dispatch a single triage document to the right analyzer(s).

    A document may contain any of: 'acl', 'policy', 'listing'. The bucket
    name is read from 'bucket' (default 'unknown').
    """
    bucket = str(doc.get("bucket", "unknown"))
    findings: list[Finding] = []
    if isinstance(doc.get("acl"), dict):
        findings.extend(analyze_acl(bucket, doc["acl"]))
    if isinstance(doc.get("policy"), dict):
        findings.extend(analyze_policy(bucket, doc["policy"]))
    if isinstance(doc.get("listing"), dict):
        findings.extend(analyze_listing(bucket, doc["listing"]))
    return findings


def summarize(findings: Iterable[Finding]) -> dict[str, Any]:
    findings = list(findings)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    top = max(
        (f.severity for f in findings),
        key=lambda s: SEVERITY_ORDER.get(s, -1),
        default=Severity.INFO,
    )
    return {
        "total": len(findings),
        "by_severity": counts,
        "highest_severity": top if findings else Severity.INFO,
    }
