import os
import secrets

TOKEN_FILE = os.path.join(os.path.dirname(__file__), 'token.txt')


def get_token():
    # Prefer explicit env var for CI/automation
    env = os.environ.get('DEMO_UI_TOKEN')
    if env:
        return env

    # Else, read or generate a token file next to UI
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE) as f:
                return f.read().strip()
        else:
            tok = secrets.token_urlsafe(16)
            with open(TOKEN_FILE, 'w') as f:
                f.write(tok)
            print(f"[demo] generated UI token and saved to {TOKEN_FILE}: {tok}")
            return tok
    except Exception:
        # fallback to ephemeral token
        return secrets.token_urlsafe(12)
