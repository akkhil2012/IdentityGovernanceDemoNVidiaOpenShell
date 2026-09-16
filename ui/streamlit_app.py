import os
import sys
import json
import time

repo_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, repo_root)

import streamlit as st
from identity.identity import IdentityManager
from triage.triage import TriageServer
from sandbox.openshell_shim import OpenShellShim
from audit.audit import AuditLogger
from agents.specialist_agent import SpecialistAgent


def ensure_env():
    os.makedirs('data', exist_ok=True)
    files = {
        'data/fraud_data.txt': 'fraud agent private data\n',
        'data/offers_data.txt': 'offers agent private data\n',
        'data/servicing_data.txt': 'servicing agent private data\n',
        'data/shared.txt': 'shared data visible to some agents\n',
    }
    for p, c in files.items():
        if not os.path.exists(p):
            with open(p, 'w') as f:
                f.write(c)


def load_policies():
    with open('agents_config.json') as f:
        cfg = json.load(f)
    return {a['id']: a['policy'] for a in cfg['agents']}


def create_services():
    policies = load_policies()
    openshell_cmd = os.environ.get('OPEN_SHELL_CMD')
    sandbox = OpenShellShim(policies, openshell_cmd)
    audit = AuditLogger('audit/audit.jsonl')
    identity = IdentityManager()
    triage = TriageServer('triage-1', 'supersecret-key', identity)

    fraud = SpecialistAgent('fraud_agent', sandbox, identity, audit)
    offers = SpecialistAgent('offers_agent', sandbox, identity, audit)
    servicing = SpecialistAgent('servicing_agent', sandbox, identity, audit)

    return {
        'sandbox': sandbox,
        'audit': audit,
        'identity': identity,
        'triage': triage,
        'agents': {'fraud_agent': fraud, 'offers_agent': offers, 'servicing_agent': servicing}
    }


st.set_page_config(page_title='Identity Governance + OpenShell Demo', layout='wide')
st.title('Identity Governance + OpenShell — Demo UI')
st.markdown('Demonstrates two independent enforcement layers: OpenShell sandbox and identity governance.')

ensure_env()
services = create_services()

# Require a demo token before allowing actions in the Streamlit UI.
from ui.auth import get_token as _get_token
_UI_TOKEN = _get_token()

def _check_token_input():
    # store token in session state
    if 'ui_token' not in st.session_state:
        st.session_state['ui_token'] = ''
    tok = st.sidebar.text_input('Demo token', type='password')
    if not tok:
        st.sidebar.warning('Enter the demo token to enable controls (see ui/token.txt or set DEMO_UI_TOKEN).')
        return False
    if tok != _UI_TOKEN:
        st.sidebar.error('Invalid token')
        return False
    st.session_state['ui_token'] = tok
    return True

if not _check_token_input():
    st.stop()

col1, col2 = st.columns([1,2])

with col1:
    st.header('Controls')
    if st.button('Run Scenario 1: Sandbox-only denial'):
        cred1 = services['triage'].issue(user_id='alice', specialist_id='fraud_agent', allowed_intents=['read:data/offers_data.txt'], ttl_seconds=300)
        res = services['agents']['fraud_agent'].attempt_read(cred1, 'data/offers_data.txt')
        st.success('Scenario 1 executed')
        st.json(res)

    if st.button('Run Scenario 2: Identity-only denial'):
        cred2 = services['triage'].issue(user_id='bob', specialist_id='offers_agent', allowed_intents=['read:data/offers_data.txt'], ttl_seconds=300)
        res = services['agents']['offers_agent'].attempt_network(cred2, 'api.payments.local')
        st.success('Scenario 2 executed')
        st.json(res)

    if st.button('Run Scenario 3: Runtime revocation'):
        cred3 = services['triage'].issue(user_id='carol', specialist_id='servicing_agent', allowed_intents=['read:data/servicing_data.txt'], ttl_seconds=300)
        res1 = services['agents']['servicing_agent'].attempt_read(cred3, 'data/servicing_data.txt')
        services['identity'].revoke(cred3['credential_id'])
        res2 = services['agents']['servicing_agent'].attempt_read(cred3, 'data/servicing_data.txt')
        st.success('Scenario 3 executed')
        st.json({'first': res1, 'second_after_revocation': res2})

    if st.button('Run All Scenarios'):
        st.write('Running all scenarios...')
        # run sequentially and show
        st.write('Scenario 1:')
        cred1 = services['triage'].issue(user_id='alice', specialist_id='fraud_agent', allowed_intents=['read:data/offers_data.txt'], ttl_seconds=300)
        st.json(services['agents']['fraud_agent'].attempt_read(cred1, 'data/offers_data.txt'))
        st.write('Scenario 2:')
        cred2 = services['triage'].issue(user_id='bob', specialist_id='offers_agent', allowed_intents=['read:data/offers_data.txt'], ttl_seconds=300)
        st.json(services['agents']['offers_agent'].attempt_network(cred2, 'api.payments.local'))
        st.write('Scenario 3:')
        cred3 = services['triage'].issue(user_id='carol', specialist_id='servicing_agent', allowed_intents=['read:data/servicing_data.txt'], ttl_seconds=300)
        st.json(services['agents']['servicing_agent'].attempt_read(cred3, 'data/servicing_data.txt'))
        services['identity'].revoke(cred3['credential_id'])
        st.json(services['agents']['servicing_agent'].attempt_read(cred3, 'data/servicing_data.txt'))

with col2:
    st.header('Audit Trail')
    entries = []
    if os.path.exists('audit/audit.jsonl'):
        with open('audit/audit.jsonl') as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    if entries:
        import pandas as pd
        df = pd.DataFrame(entries)
        df['ts_human'] = pd.to_datetime(df['ts'], unit='s')
        st.dataframe(df[['ts_human', 'user_id', 'specialist', 'intent', 'identity_gate', 'sandbox_gate', 'final_decision']].sort_values('ts_human', ascending=False))

        # interactive chart: counts by specialist and decision using plotly
        try:
            import plotly.express as px
            chart_df = df.groupby(['specialist', 'final_decision']).size().reset_index(name='count')
            fig = px.bar(chart_df, x='specialist', y='count', color='final_decision', barmode='group', title='Decisions by Specialist')
            st.plotly_chart(fig, use_container_width=True)
        except Exception:
            st.write('Install plotly to view interactive charts')

        # CSV export
        csv = df.to_csv(index=False)
        st.download_button('Download audit CSV', csv, file_name='audit.csv', mime='text/csv')

        # PNG export: render a small matplotlib chart and provide download
        try:
            import matplotlib.pyplot as plt
            import io
            fig2, ax = plt.subplots()
            summary = df['final_decision'].value_counts()
            summary.plot(kind='bar', ax=ax)
            ax.set_title('Allow vs Deny')
            buf = io.BytesIO()
            fig2.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            st.download_button('Download decision PNG', buf, file_name='decisions.png', mime='image/png')
            plt.close(fig2)
        except Exception:
            st.write('Matplotlib not available to render PNG')

    else:
        st.write('No audit entries yet. Run scenarios to populate the audit trail.')

    st.markdown('---')
    st.header('Latest Entries (JSON)')
    st.write(entries[-5:])
