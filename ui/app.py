import os
import json
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session

import sys
repo_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, repo_root)

from identity.identity import IdentityManager
from triage.triage import TriageServer
from sandbox.openshell_shim import OpenShellShim
from audit.audit import AuditLogger
from agents.specialist_agent import SpecialistAgent


app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key')

from ui.auth import get_token
_UI_TOKEN = get_token()


INDEX_HTML = '''
<html>
  <head><title>Identity Governance + OpenShell Demo UI</title></head>
  <body>
    <h1>Identity Governance + OpenShell Demo</h1>
    <p>Run scenarios or inspect the audit trail.</p>
    <form action="/run_scenario/1" method="post"><button type="submit">Run Scenario 1 (Sandbox-only denial)</button></form>
    <form action="/run_scenario/2" method="post"><button type="submit">Run Scenario 2 (Identity-only denial)</button></form>
    <form action="/run_scenario/3" method="post"><button type="submit">Run Scenario 3 (Runtime revocation)</button></form>
    <form action="/run_all" method="post"><button type="submit">Run All Scenarios</button></form>
    <h2>Audit Trail</h2>
    <a href="/audit">View audit (JSONL)</a>
  </body>
</html>
'''


def make_env():
    os.makedirs('data', exist_ok=True)
    # ensure data files exist
    with open('data/fraud_data.txt', 'w') as f:
        f.write('fraud agent private data\n')
    with open('data/offers_data.txt', 'w') as f:
        f.write('offers agent private data\n')
    with open('data/servicing_data.txt', 'w') as f:
        f.write('servicing agent private data\n')
    with open('data/shared.txt', 'w') as f:
        f.write('shared data visible to some agents\n')


def create_services():
    policies = json.load(open('agents_config.json'))
    policies = {a['id']: a['policy'] for a in policies['agents']}
    openshell_cmd = os.environ.get('OPEN_SHELL_CMD')
    sandbox = OpenShellShim(policies, openshell_cmd)
    audit = AuditLogger('audit/audit.jsonl')
    identity = IdentityManager()
    triage = TriageServer('triage-1', 'supersecret-key', identity)

    fraud = SpecialistAgent('fraud_agent', sandbox, identity, audit)
    offers = SpecialistAgent('offers_agent', sandbox, identity, audit)
    servicing = SpecialistAgent('servicing_agent', sandbox, identity, audit)

    services = {
        'sandbox': sandbox,
        'audit': audit,
        'identity': identity,
        'triage': triage,
        'agents': {'fraud_agent': fraud, 'offers_agent': offers, 'servicing_agent': servicing}
    }
    return services


@app.route('/')
def index():
    if not session.get('authorized'):
        return redirect(url_for('login'))
    return render_template_string(INDEX_HTML)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form.get('token') or request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
        if token == _UI_TOKEN:
            session['authorized'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string('<p>Invalid token</p><a href="/login">Try again</a>'), 401
    return render_template_string('''
        <form method="post">
          <label>Enter demo token: <input type="password" name="token" /></label>
          <button type="submit">Login</button>
        </form>
    ''')


def _auth_check():
    # Accept Authorization header for API automation too
    authh = request.headers.get('Authorization')
    if authh and authh.startswith('Bearer '):
        token = authh.removeprefix('Bearer ').strip()
        if token == _UI_TOKEN:
            return True
    return session.get('authorized')


@app.route('/run_scenario/<int:n>', methods=['POST'])
def run_scenario(n):
    make_env()
    if not _auth_check():
        return jsonify({'error': 'unauthorized'}), 401
    svc = create_services()
    triage = svc['triage']
    identity = svc['identity']
    agents = svc['agents']

    if n == 1:
        cred1 = triage.issue(user_id='alice', specialist_id='fraud_agent', allowed_intents=['read:data/offers_data.txt'], ttl_seconds=300)
        res = agents['fraud_agent'].attempt_read(cred1, 'data/offers_data.txt')
    elif n == 2:
        cred2 = triage.issue(user_id='bob', specialist_id='offers_agent', allowed_intents=['read:data/offers_data.txt'], ttl_seconds=300)
        res = agents['offers_agent'].attempt_network(cred2, 'api.payments.local')
    elif n == 3:
        cred3 = triage.issue(user_id='carol', specialist_id='servicing_agent', allowed_intents=['read:data/servicing_data.txt'], ttl_seconds=300)
        res1 = agents['servicing_agent'].attempt_read(cred3, 'data/servicing_data.txt')
        identity.revoke(cred3['credential_id'])
        res2 = agents['servicing_agent'].attempt_read(cred3, 'data/servicing_data.txt')
        res = {'first': res1, 'second_after_revocation': res2}
    else:
        return jsonify({'error': 'unknown scenario'}), 400

    return jsonify(res)


@app.route('/run_all', methods=['POST'])
def run_all():
    if not _auth_check():
        return jsonify({'error': 'unauthorized'}), 401
    results = {}
    for i in [1,2,3]:
        resp = run_scenario(i)
        results[f'scenario_{i}'] = resp.get_json() if hasattr(resp, 'get_json') else resp
    return jsonify(results)


@app.route('/audit')
def view_audit():
    if not _auth_check():
        return jsonify({'error': 'unauthorized'}), 401
    entries = []
    if os.path.exists('audit/audit.jsonl'):
        with open('audit/audit.jsonl') as f:
            for line in f:
                entries.append(json.loads(line))
    return jsonify(entries)


@app.route('/export/audit.csv')
def export_audit_csv():
    if not _auth_check():
        return jsonify({'error': 'unauthorized'}), 401
    import io
    import csv
    entries = []
    if os.path.exists('audit/audit.jsonl'):
        with open('audit/audit.jsonl') as f:
            for line in f:
                entries.append(json.loads(line))
    if not entries:
        return jsonify({'error': 'no audit entries'}), 404
    # flatten entries for CSV
    keys = set()
    for e in entries:
        keys.update(e.keys())
    keys = list(keys)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    for e in entries:
        writer.writerow(e)
    output.seek(0)
    return (output.getvalue(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="audit.csv"'})


@app.route('/export/decisions.png')
def export_decision_png():
    if not _auth_check():
        return jsonify({'error': 'unauthorized'}), 401
    import io
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return jsonify({'error': 'matplotlib not available'}), 500
    entries = []
    if os.path.exists('audit/audit.jsonl'):
        with open('audit/audit.jsonl') as f:
            for line in f:
                entries.append(json.loads(line))
    if not entries:
        return jsonify({'error': 'no audit entries'}), 404
    # quick bar chart of allow/deny
    import pandas as pd
    df = pd.DataFrame(entries)
    summary = df['final_decision'].value_counts()
    fig, ax = plt.subplots()
    summary.plot(kind='bar', ax=ax)
    ax.set_title('Allow vs Deny')
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    plt.close(fig)
    return (buf.getvalue(), 200, {'Content-Type': 'image/png', 'Content-Disposition': 'attachment; filename="decisions.png"'})


if __name__ == '__main__':
    make_env()
    app.run(port=8080, debug=True)
