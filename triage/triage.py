import random
from typing import List


class TriageServer:
    """Simple MCP-style triage server that issues credentials via an IdentityManager.

    For demo purposes we allow explicit allowed_intents to be passed in. In a real
    system this would classify free-text and choose scopes accordingly.
    """

    def __init__(self, triage_id: str, secret: str, identity_manager):
        self.triage_id = triage_id
        self.secret = secret
        self.identity = identity_manager
        # Register ourselves as an issuer with the identity layer
        self.identity.register_issuer(triage_id, secret)

    def issue(self, user_id: str, specialist_id: str, allowed_intents: List[str], ttl_seconds: int = 60):
        return self.identity.issue_credential(user_id, self.triage_id, specialist_id, allowed_intents, ttl_seconds)

    def classify_and_route(self, user_query: str):
        # Primitive classifier for demo
        q = user_query.lower()
        if "fraud" in q or "dispute" in q:
            return "fraud_agent"
        if "offer" in q or "promo" in q:
            return "offers_agent"
        return "servicing_agent"
