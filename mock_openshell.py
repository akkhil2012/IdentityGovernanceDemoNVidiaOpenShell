#!/usr/bin/env python3
import sys
import argparse

"""Mock OpenShell CLI for integration testing.

Accepts: check --agent <agent_id> --type <check_type> --target <target>
Exits 0 for allowed checks per a hard-coded allowlist, non-zero otherwise.
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', nargs='?')
    parser.add_argument('--agent')
    parser.add_argument('--type')
    parser.add_argument('--target')
    args = parser.parse_args()

    if args.cmd != 'check':
        print('error: unrecognized subcommand', file=sys.stderr)
        sys.exit(2)

    # Simple allowlist matching similar to agents_config.json
    allowed = {
        ('offers_agent', 'network', 'api.payments.local'),
        ('offers_agent', 'network', 'api.offers.local'),
        ('offers_agent', 'filesystem', 'data/offers_data.txt'),
        ('servicing_agent', 'filesystem', 'data/servicing_data.txt'),
        ('fraud_agent', 'filesystem', 'data/fraud_data.txt'),
    }

    key = (args.agent, args.type, args.target)
    if key in allowed:
        # allowed
        sys.exit(0)
    else:
        print('denied by mock openshell', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
