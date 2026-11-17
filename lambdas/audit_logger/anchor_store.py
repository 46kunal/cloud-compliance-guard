"""Anchor the audit chain's head hash somewhere a database writer cannot edit.

The hash chain in the database detects edits, but anyone who can write to the database could rewrite the
whole chain and recompute every hash. This module closes that gap with AWS-native tools:

  1. After a scan, the head hash and chain length are written as a receipt to an S3 bucket with Object Lock,
     so the receipt cannot be changed or deleted until its retention date (GOVERNANCE or COMPLIANCE mode).
  2. The receipt is signed with an asymmetric KMS key. The private key never leaves KMS, so a forged receipt
     fails verification.
  3. verify() recomputes what each receipt claims against the live chain. A rewritten, truncated or reordered
     chain no longer matches the locked, signed receipts.

What this does not stop: deleting the whole bucket (needs s3 permissions and respects Object Lock), or someone
who controls both the KMS key and the bucket. It makes silent rewriting detectable, not impossible.

Environment: ANCHOR_BUCKET, ANCHOR_KMS_KEY_ID, ANCHOR_LOCK_MODE (GOVERNANCE or COMPLIANCE, default GOVERNANCE),
ANCHOR_RETENTION_DAYS (default 30). With ANCHOR_BUCKET unset everything here is a safe no-op.
"""
import base64
import json
import os
from datetime import datetime, timedelta, timezone

PREFIX = "anchors/"
ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
RECEIPT_VERSION = 1


def configured() -> bool:
    return bool(os.environ.get("ANCHOR_BUCKET") and os.environ.get("ANCHOR_KMS_KEY_ID"))


def _clients():
    import boto3
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    return boto3.client("s3", region_name=region), boto3.client("kms", region_name=region)


def canonical(receipt: dict) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_receipt(entries: list, scan_id=None, now=None) -> dict:
    head = entries[-1]
    return {"version": RECEIPT_VERSION, "chain": "main", "sequence": len(entries), "head_hash": head["entry_hash"],
            "head_event_id": head.get("id"), "scan_id": scan_id,
            "anchored_at": (now or datetime.now(timezone.utc)).isoformat()}


def sign(kms, key_id: str, receipt: dict) -> str:
    response = kms.sign(KeyId=key_id, Message=canonical(receipt), MessageType="RAW", SigningAlgorithm=ALGORITHM)
    return base64.b64encode(response["Signature"]).decode("ascii")


def signature_valid(kms, key_id: str, receipt: dict, signature_b64: str) -> bool:
    try:
        response = kms.verify(KeyId=key_id, Message=canonical(receipt), MessageType="RAW",
                              Signature=base64.b64decode(signature_b64), SigningAlgorithm=ALGORITHM)
        return bool(response.get("SignatureValid"))
    except Exception:
        return False


def _list_keys(s3, bucket: str, limit: int) -> list:
    keys, token = [], None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": PREFIX}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        keys.extend(obj["Key"] for obj in page.get("Contents", []))
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    return sorted(keys)[-limit:]


def list_anchors(s3=None, bucket: str = None, limit: int = 50) -> list:
    """Stored receipts, oldest first. Each item: the receipt, its signature, key id, S3 key and lock retention."""
    if s3 is None:
        s3, _ = _clients()
    bucket = bucket or os.environ["ANCHOR_BUCKET"]
    anchors = []
    for key in _list_keys(s3, bucket, limit):
        body = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        retain = None
        try:
            retain = s3.head_object(Bucket=bucket, Key=key).get("ObjectLockRetainUntilDate")
        except Exception:
            pass
        anchors.append({"s3_key": key, "receipt": body["receipt"], "signature": body["signature"],
                        "key_id": body.get("key_id"), "locked_until": retain.isoformat() if retain else None})
    return anchors


def anchor(entries: list, scan_id=None) -> dict:
    """Write a signed, locked receipt for the current chain head. Skips when nothing changed since the last one."""
    if not configured():
        return {"anchored": False, "reason": "not configured"}
    if not entries:
        return {"anchored": False, "reason": "the chain is empty"}
    s3, kms = _clients()
    bucket, key_id = os.environ["ANCHOR_BUCKET"], os.environ["ANCHOR_KMS_KEY_ID"]
    mode = os.environ.get("ANCHOR_LOCK_MODE", "GOVERNANCE").upper()
    days = int(os.environ.get("ANCHOR_RETENTION_DAYS", "30"))
    previous = list_anchors(s3, bucket, limit=1)
    if previous and previous[-1]["receipt"]["head_hash"] == entries[-1]["entry_hash"] \
            and previous[-1]["receipt"]["sequence"] == len(entries):
        return {"anchored": False, "reason": "no new audit entries since the last anchor"}

    now = datetime.now(timezone.utc)
    receipt = build_receipt(entries, scan_id, now)
    body = {"receipt": receipt, "signature": sign(kms, key_id, receipt), "key_id": key_id, "algorithm": ALGORITHM}
    key = f"{PREFIX}{receipt['sequence']:010d}-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(body, sort_keys=True).encode("utf-8"),
                  ContentType="application/json", ObjectLockMode=mode,
                  ObjectLockRetainUntilDate=now + timedelta(days=days))
    return {"anchored": True, "s3_key": key, "sequence": receipt["sequence"], "head_hash": receipt["head_hash"],
            "lock_mode": mode, "locked_until": (now + timedelta(days=days)).isoformat()}


def verify(entries: list, anchors: list, kms=None, key_id: str = None) -> dict:
    """Check every stored receipt against the live chain. status is VERIFIED, MISMATCH or NO_ANCHORS."""
    if kms is None:
        _, kms = _clients()
    key_id = key_id or os.environ.get("ANCHOR_KMS_KEY_ID")
    results, ok = [], True
    for item in anchors:
        receipt = item["receipt"]
        sequence, head = receipt["sequence"], receipt["head_hash"]
        signature_ok = signature_valid(kms, item.get("key_id") or key_id, receipt, item["signature"])
        if len(entries) < sequence:
            matches, reason = False, "the chain is now shorter than when this receipt was signed (entries were removed)"
        elif entries[sequence - 1]["entry_hash"] != head:
            matches, reason = False, "the entry at this position has a different hash (the chain was rewritten)"
        else:
            matches, reason = True, None
        if not signature_ok:
            reason = "the signature does not verify, so this receipt was not issued by the signing key"
        results.append({"s3_key": item["s3_key"], "sequence": sequence, "head_hash": head,
                        "anchored_at": receipt.get("anchored_at"), "locked_until": item.get("locked_until"),
                        "signature_valid": signature_ok, "matches_chain": matches, "reason": reason})
        ok = ok and signature_ok and matches
    if not anchors:
        status = "NO_ANCHORS"
    else:
        status = "VERIFIED" if ok else "MISMATCH"
    latest = max((r["sequence"] for r in results), default=0)
    return {"status": status, "anchors": results, "entries": len(entries),
            "entries_after_last_anchor": max(0, len(entries) - latest)}
