import os
import json
import sys
repo_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, repo_root)
from sandbox.openshell_shim import OpenShellShim


def run_test():
    repo_root = os.path.dirname(os.path.dirname(__file__))
    mock_path = os.path.join(repo_root, 'mock_openshell.py')
    # Configure shim to use the mock Python script
    policies = {
        'offers_agent': {'files': ['data/offers_data.txt'], 'network': ['api.offers.local', 'api.payments.local'], 'spawn': []},
        'fraud_agent': {'files': ['data/fraud_data.txt'], 'network': [], 'spawn': []},
        'servicing_agent': {'files': ['data/servicing_data.txt'], 'network': ['api.servicing.local'], 'spawn': []},
    }

    shim = OpenShellShim(policies, openshell_cmd=mock_path)

    print('Using openshell_cmd:', shim.openshell_cmd)

    # Test network check (should be allowed for offers_agent -> api.payments.local)
    ok, reason = shim.check_network('offers_agent', 'api.payments.local')
    print('offers_agent network api.payments.local ->', ok, reason)

    # Test filesystem check (fraud agent trying to read offers_data -> should be denied)
    ok2, reason2 = shim.check_filesystem('fraud_agent', 'data/offers_data.txt')
    print('fraud_agent filesystem data/offers_data.txt ->', ok2, reason2)

    # Test filesystem allowed (servicing_agent reading servicing_data)
    ok3, reason3 = shim.check_filesystem('servicing_agent', 'data/servicing_data.txt')
    print('servicing_agent filesystem data/servicing_data.txt ->', ok3, reason3)

    # Print a summary exit code
    if ok and (not ok2) and ok3:
        print('MOCK CLI INTEGRATION: SUCCESS')
        return 0
    else:
        print('MOCK CLI INTEGRATION: FAILURE')
        return 2


if __name__ == '__main__':
    sys.exit(run_test())
