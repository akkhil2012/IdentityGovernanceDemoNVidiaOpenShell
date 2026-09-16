# Identity Governance and NVIDIA OpenShell: A Two-Layer Demo for Agentic Banking Systems

This demo shows two distinct enforcement layers: an OS-level sandbox (NVIDIA OpenShell semantics, here implemented as a clearly-labeled shim) and an identity governance layer (credential issuance, verification, and revocation).

Run the demo with Python 3.8+:

```bash
python demo.py
```

Notes:
- The OpenShell integration is a shim (see `sandbox/openshell_shim.py`) that enforces per-agent allowlists for filesystem, network, and process-spawn. Replace with the real OpenShell invocation in production; the code marks where to substitute the real calls.
- Credentials are signed with HMAC (symmetric key) for simplicity, carry a delegation chain, short TTL, and support immediate revocation.

See `demo.py` for the three required scenarios and `audit/audit.jsonl` for the final audit trail.

## Architecture diagram

Below is a simple ASCII/diagram showing the flow of the demo. It illustrates the two independent enforcement layers (OpenShell sandbox and Identity governance) and how they feed a shared audit trail.

User -> Triage Server -> Identity Governance (issues signed credential)
														 |                      
														 v                      
										Specialist Agent(s) --(OpenShell Sandbox)--> OS-level checks
														 |                                   
														 v                                   
													Audit Trail <---------------------------

Mermaid view (optional):

```mermaid
flowchart LR
	User[User]
	Triage[Triage Server]
	Identity[Identity Governance]
	Agents[Specialist Agents]
	Sandbox[OpenShell Sandbox (policy per-agent)]
	Audit[Audit Trail (JSONL)]

	User --> Triage --> Identity --> Agents
	Agents --> Sandbox
	Agents --> Audit
	Identity --> Audit
	Triage --> Audit
```

Notes:
- The demo intentionally keeps identity checks and sandbox checks separate in code; both are executed and logged for every action so auditors can see both gate outcomes independently.
- Replace the OpenShell shim in `sandbox/openshell_shim.py` with the real NVIDIA OpenShell invocation for a production/live demo.
