import json
import os
import time

from identity.identity import IdentityManager
from triage.triage import TriageServer
from sandbox.openshell_shim import OpenShellShim
from audit.audit import AuditLogger
from agents.specialist_agent import SpecialistAgent


def ensure_data_files():
    os.makedirs("data", exist_ok=True)
    with open("data/fraud_data.txt", "w") as f:
        f.write("fraud agent private data\n")
    with open("data/offers_data.txt", "w") as f:
        f.write("offers agent private data\n")
    with open("data/servicing_data.txt", "w") as f:
        f.write("servicing agent private data\n")
    with open("data/shared.txt", "w") as f:
        f.write("shared data visible to some agents\n")


def load_agent_policies(path="agents_config.json"):
    with open(path) as f:
        cfg = json.load(f)
    policies = {a["id"]: a["policy"] for a in cfg["agents"]}
    return policies


def main():
    print("Setting up demo environment...")
    ensure_data_files()
    policies = load_agent_policies()
    # Allow demo runner to specify a real OpenShell CLI via OPEN_SHELL_CMD env var.
    openshell_cmd = os.environ.get("OPEN_SHELL_CMD")
    sandbox = OpenShellShim(policies, openshell_cmd)
    audit = AuditLogger("audit/audit.jsonl")
    identity = IdentityManager()

    # Create a triage server (issuer)
    triage = TriageServer("triage-1", "supersecret-key", identity)

    # Instantiate agents
    fraud = SpecialistAgent("fraud_agent", sandbox, identity, audit)
    offers = SpecialistAgent("offers_agent", sandbox, identity, audit)
    servicing = SpecialistAgent("servicing_agent", sandbox, identity, audit)

    print("\nScenario 1: Sandbox-only denial")
    # We will give fraud_agent a credential that *allows* reading offers_data.txt (identity would pass),
    # but fraud_agent's sandbox policy does not allow it -> sandbox should deny.
    cred1 = triage.issue(user_id="alice", specialist_id="fraud_agent", allowed_intents=["read:data/offers_data.txt"], ttl_seconds=300)
    res1 = fraud.attempt_read(cred1, "data/offers_data.txt")
    print("Result:", res1["final_decision"], "| identity:", res1["identity_gate"], "| sandbox:", res1["sandbox_gate"])

    time.sleep(1)
    print("\nScenario 2: Identity-only denial")
    # offers_agent sandbox allows network to api.payments.local, but we will issue a credential that lacks that intent.
    cred2 = triage.issue(user_id="bob", specialist_id="offers_agent", allowed_intents=["read:data/offers_data.txt"], ttl_seconds=300)
    res2 = offers.attempt_network(cred2, "api.payments.local")
    print("Result:", res2["final_decision"], "| identity:", res2["identity_gate"], "| sandbox:", res2["sandbox_gate"])

    time.sleep(1)
    print("\nScenario 3: Runtime revocation")
    # Issue a credential to servicing_agent and use it once, then revoke and show next call fails.
    cred3 = triage.issue(user_id="carol", specialist_id="servicing_agent", allowed_intents=["read:data/servicing_data.txt"], ttl_seconds=300)
    res3a = servicing.attempt_read(cred3, "data/servicing_data.txt")
    print("First call result:", res3a["final_decision"], "| identity:", res3a["identity_gate"], "| sandbox:", res3a["sandbox_gate"])

    # Revoke the credential at runtime
    print("Revoking credential id:", cred3["credential_id"])
    identity.revoke(cred3["credential_id"])

    # Immediately attempt another action using the same credential
    res3b = servicing.attempt_read(cred3, "data/servicing_data.txt")
    print("Second call after revocation result:", res3b["final_decision"], "| identity:", res3b["identity_gate"], "| sandbox:", res3b["sandbox_gate"])

    print("\nDemo complete. Audit trail written to 'audit/audit.jsonl'\n")


if __name__ == "__main__":
    main()
