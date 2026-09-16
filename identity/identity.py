import json
import time
import hmac
import hashlib
import uuid
from typing import Dict, Any, List, Tuple


class IdentityManager:
    """Simple identity governance layer.

    - Registers issuers (triage servers) with symmetric secrets.
    - Issues short-lived HMAC-signed credentials including delegation chain.
    - Verifies credentials for specialist agents and intents.
    - Supports immediate revocation by credential id.
    """

    def __init__(self):
        self.issuers: Dict[str, str] = {}
        self.revoked = set()

    def register_issuer(self, issuer_id: str, secret: str):
        self.issuers[issuer_id] = secret

    def issue_credential(self, user_id: str, triage_id: str, specialist_id: str, allowed_intents: List[str], ttl_seconds: int = 60) -> Dict[str, Any]:
        if triage_id not in self.issuers:
            raise ValueError("unknown issuer")
        cid = str(uuid.uuid4())
        issued_at = int(time.time())
        expires_at = issued_at + ttl_seconds
        cred = {
            "credential_id": cid,
            "user_id": user_id,
            "triage_id": triage_id,
            "specialist_id": specialist_id,
            "allowed_intents": allowed_intents,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "delegation_chain": [
                {"type": "user", "id": user_id},
                {"type": "triage", "id": triage_id},
            ],
        }
        payload = json.dumps(cred, sort_keys=True).encode()
        secret = self.issuers[triage_id].encode()
        sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        cred["sig"] = sig
        return cred

    def verify_credential(self, cred: Dict[str, Any], specialist_id: str, intent: str) -> Tuple[bool, str]:
        # Basic structural checks
        try:
            cid = cred["credential_id"]
            triage_id = cred["triage_id"]
            expires_at = int(cred["expires_at"])
        except Exception:
            return False, "malformed_credential"

        if cid in self.revoked:
            return False, "revoked"

        now = int(time.time())
        if now > expires_at:
            return False, "expired"

        if triage_id not in self.issuers:
            return False, "unknown_issuer"

        # Verify signature
        sig = cred.get("sig")
        copy = {k: v for k, v in cred.items() if k != "sig"}
        payload = json.dumps(copy, sort_keys=True).encode()
        secret = self.issuers[triage_id].encode()
        expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False, "bad_signature"

        # Verify specialist match
        if cred.get("specialist_id") != specialist_id:
            return False, "wrong_specialist"

        # Verify intent in allowed_intents (exact match)
        if intent not in cred.get("allowed_intents", []):
            return False, "intent_not_allowed"

        return True, "ok"

    def revoke(self, credential_id: str):
        self.revoked.add(credential_id)

    def is_revoked(self, credential_id: str) -> bool:
        return credential_id in self.revoked
