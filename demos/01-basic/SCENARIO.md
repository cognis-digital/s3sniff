# Demo 01 — Basic open-bucket triage

This scenario shows S3SNIFF flagging a misconfigured bucket from an
authorized configuration snapshot. **No network access is performed** — the
input is an offline export of the kind produced by:

```
aws s3api get-bucket-acl    --bucket my-bucket
aws s3api get-bucket-policy --bucket my-bucket
```

plus an optional listing snapshot. S3SNIFF is detection/triage only; it never
mutates or attacks anything.

## Input

`buckets.json` contains two documents:

1. `acme-public-assets` — an intentionally public asset host (read-only),
   but its bucket **policy** also grants `s3:PutObject` to `Principal: "*"`,
   which is a real misconfiguration (anyone can upload).
2. `acme-internal-backups` — its **ACL** grants `READ` to `AllUsers`, and its
   anonymous **listing** succeeded, exposing a `db-backup.sql` object.

## Run it

```
python -m s3sniff scan demos/01-basic/buckets.json
# machine-readable:
python -m s3sniff scan demos/01-basic/buckets.json --format json
```

## Expected outcome

- `acme-public-assets`: **CRITICAL** public write (`POLICY_PUBLIC_WRITE`).
- `acme-internal-backups`: **HIGH** public-read ACL
  (`ACL_PUBLIC_READ`), **HIGH** publicly enumerable listing
  (`LISTING_PUBLIC_ENUMERABLE`), and **MEDIUM** sensitive object
  (`LISTING_SENSITIVE_OBJECT` on `db-backup.sql`).
- Process exits with code **2** (findings present).

## Remediation (summarized in tool output)

Enable S3 Block Public Access at account + bucket scope, remove the `*`
principal grants, and rotate anything exposed in the backups bucket.
