import os
import sys
repo_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, repo_root)

from app import app
from auth import get_token

def run_tests():
    client = app.test_client()
    # perform login first
    token = get_token()
    r_login = client.post('/login', data={'token': token})
    if r_login.status_code not in (200, 302):
        print('login failed', r_login.status_code)
        return
    r = client.get('/')
    print('GET / ->', r.status_code)
    r1 = client.post('/run_scenario/1')
    print('/run_scenario/1 ->', r1.status_code, r1.get_json())
    r2 = client.post('/run_scenario/2')
    print('/run_scenario/2 ->', r2.status_code, r2.get_json())
    r3 = client.post('/run_scenario/3')
    print('/run_scenario/3 ->', r3.status_code, r3.get_json())
    r4 = client.get('/audit')
    print('/audit ->', r4.status_code, 'entries:', len(r4.get_json()))

if __name__ == '__main__':
    run_tests()
