import os
from typing import Dict, Any, Tuple


class SpecialistAgent:
    """A specialist agent that performs actions guarded by two independent gates:
    - Identity gate (calls into IdentityManager.verify_credential)
    - Sandbox gate (OpenShellShim checks)

    Both results are always logged to the AuditLogger by the caller.
    """

    def __init__(self, agent_id: str, sandbox, identity_manager, audit_logger):
        self.agent_id = agent_id
        self.sandbox = sandbox
        self.identity = identity_manager
        self.audit = audit_logger

    def attempt_read(self, cred: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        intent = f"read:{file_path}"
        # Identity check
        id_ok, id_reason = self.identity.verify_credential(cred, self.agent_id, intent)

        # Sandbox check (OpenShell)
        sb_ok, sb_reason = self.sandbox.check_filesystem(self.agent_id, file_path)

        final = False
        notes = []
        if id_ok and sb_ok:
            # perform the read
            try:
                with open(file_path, "r") as f:
                    data = f.read()
                final = True
                notes.append("read_succeeded")
            except Exception as e:
                notes.append(f"read_error:{e}")
        else:
            if not id_ok:
                notes.append(f"identity_denied:{id_reason}")
            if not sb_ok:
                notes.append(f"sandbox_denied:{sb_reason}")

        entry = {
            "user_id": cred.get("user_id"),
            "delegation_chain": cred.get("delegation_chain"),
            "credential_id": cred.get("credential_id"),
            "specialist": self.agent_id,
            "intent": intent,
            "target": file_path,
            "identity_gate": {"ok": id_ok, "reason": id_reason},
            "sandbox_gate": {"ok": sb_ok, "reason": sb_reason},
            "final_decision": "allow" if final else "deny",
            "notes": notes,
        }
        self.audit.log(entry)
        return entry

    def attempt_network(self, cred: Dict[str, Any], dest: str) -> Dict[str, Any]:
        intent = f"network:{dest}"
        id_ok, id_reason = self.identity.verify_credential(cred, self.agent_id, intent)
        sb_ok, sb_reason = self.sandbox.check_network(self.agent_id, dest)

        final = False
        notes = []
        if id_ok and sb_ok:
            # Simulate a network call success
            final = True
            notes.append("network_call_simulated")
        else:
            if not id_ok:
                notes.append(f"identity_denied:{id_reason}")
            if not sb_ok:
                notes.append(f"sandbox_denied:{sb_reason}")

        entry = {
            "user_id": cred.get("user_id"),
            "delegation_chain": cred.get("delegation_chain"),
            "credential_id": cred.get("credential_id"),
            "specialist": self.agent_id,
            "intent": intent,
            "target": dest,
            "identity_gate": {"ok": id_ok, "reason": id_reason},
            "sandbox_gate": {"ok": sb_ok, "reason": sb_reason},
            "final_decision": "allow" if final else "deny",
            "notes": notes,
        }
        self.audit.log(entry)
        return entry
