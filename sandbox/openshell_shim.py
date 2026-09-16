import os
import shutil
import subprocess
import sys
from typing import Dict, Tuple, Optional


class OpenShellShim:
    """A shim that either calls a real OpenShell CLI (if available and configured)
    or falls back to an in-process policy checker.

    Usage:
      - Pass `openshell_cmd=None` (default) to auto-detect `openshell` on PATH. If found,
        the shim will attempt to call it for checks. If not found, the in-process allowlist
        policy is used.
      - Alternatively, set the environment variable `OPEN_SHELL_CMD` to the desired
        CLI path and pass it here. The exact CLI arguments used are placeholders and must
        be adjusted to the real OpenShell invocation syntax. See comments below.

    NOTE: For this demo we cannot guarantee the target environment has NVIDIA OpenShell.
    The code below attempts to call a CLI named `openshell` with a simple check command
    pattern; if you plan to demo with the real OpenShell, replace the `self._call_real`
    implementation with the correct command line and parsing logic according to the
    OpenShell version you have.
    """

    def __init__(self, policies: Dict[str, Dict], openshell_cmd: Optional[str] = None):
        # policies is a dict keyed by agent_id with fields 'files', 'network', 'spawn'
        self.policies = policies
        self.openshell_cmd = openshell_cmd or os.environ.get("OPEN_SHELL_CMD")
        if not self.openshell_cmd:
            self.openshell_cmd = shutil.which("openshell")
        self.use_real = bool(self.openshell_cmd)

    def _call_real(self, check_type: str, agent_id: str, target: str) -> Tuple[bool, str]:
        """Call the real OpenShell CLI. This implementation is a conservative placeholder:
        it runs: <openshell_cmd> check --agent <agent_id> --type <check_type> --target <target>
        and treats exit code 0 as allowed. Replace with the real syntax for your OpenShell.
        """
        try:
            # If the configured command is a Python script, run it with the current Python interpreter
            if str(self.openshell_cmd).endswith(".py"):
                cmd = [sys.executable, self.openshell_cmd, "check", "--agent", agent_id, "--type", check_type, "--target", target]
            else:
                cmd = [self.openshell_cmd, "check", "--agent", agent_id, "--type", check_type, "--target", target]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, f"allowed_by_openshell_cli"
            else:
                return False, f"denied_by_openshell_cli: {res.returncode} {res.stdout.strip()} {res.stderr.strip()}"
        except FileNotFoundError:
            return False, "openshell_cli_not_found"
        except Exception as e:
            return False, f"openshell_cli_error:{e}"

    def check_filesystem(self, agent_id: str, path: str) -> Tuple[bool, str]:
        # Prefer calling real OpenShell CLI when configured
        if self.use_real:
            ok, reason = self._call_real("filesystem", agent_id, path)
            # If the CLI appears incompatible (different subcommands), fall back to shim
            if "unrecognized subcommand" in reason or "openshell_cli_not_found" in reason or "openshell_cli_error" in reason:
                # disable future real-CLI attempts and fall back
                self.use_real = False
            else:
                return ok, reason

        pol = self.policies.get(agent_id, {})
        allowed = pol.get("files", [])
        norm = os.path.normpath(path)
        for a in allowed:
            if norm == os.path.normpath(a) or norm.startswith(os.path.normpath(a) + os.sep):
                return True, "allowed_by_policy"
        return False, "denied_by_openshell_shim"

    def check_network(self, agent_id: str, dest: str) -> Tuple[bool, str]:
        if self.use_real:
            ok, reason = self._call_real("network", agent_id, dest)
            if "unrecognized subcommand" in reason or "openshell_cli_not_found" in reason or "openshell_cli_error" in reason:
                self.use_real = False
            else:
                return ok, reason

        pol = self.policies.get(agent_id, {})
        allowed = pol.get("network", [])
        if dest in allowed:
            return True, "allowed_by_policy"
        return False, "denied_by_openshell_shim"

    def check_spawn(self, agent_id: str, proc_name: str) -> Tuple[bool, str]:
        if self.use_real:
            ok, reason = self._call_real("spawn", agent_id, proc_name)
            if "unrecognized subcommand" in reason or "openshell_cli_not_found" in reason or "openshell_cli_error" in reason:
                self.use_real = False
            else:
                return ok, reason

        pol = self.policies.get(agent_id, {})
        allowed = pol.get("spawn", [])
        if proc_name in allowed:
            return True, "allowed_by_policy"
        return False, "denied_by_openshell_shim"
