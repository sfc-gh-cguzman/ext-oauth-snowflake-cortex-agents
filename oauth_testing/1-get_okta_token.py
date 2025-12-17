import requests
import secrets
import hashlib
import base64
import webbrowser
import os
from urllib.parse import urlencode, urlparse, parse_qs
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- CONFIGURATION ---
# Configuration loaded from .env file
ISSUER = os.getenv("OKTA_ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
SCOPE = os.getenv("SCOPE", "session:role-any offline_access")

def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')
    return code_verifier, code_challenge

def get_tokens():
    # 1. Generate PKCE (Security requirement)
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    # 2. Create the Login URL
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPE,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    }
    auth_url = f"{ISSUER}/v1/authorize?{urlencode(params)}"

    print("--- STEP 1: LOG IN ---")
    print("I am opening a browser for you to log in.")
    print(f"If it doesn't open, copy this URL:\n{auth_url}")
    webbrowser.open(auth_url)

    # 3. Capture the Code
    print("\n--- STEP 2: COPY THE URL ---")
    print("After you log in, the browser will go to a 'localhost' page.")
    print("It might say 'Site can't be reached' - THAT IS FINE.")
    print("Look at the address bar at the top of your browser.")
    print("Copy the ENTIRE URL (starting with http://localhost...) and paste it below:")
    
    redirect_response = input("\nPaste full URL here: ").strip()

    # Parse the code from the URL
    parsed_url = urlparse(redirect_response)
    code = parse_qs(parsed_url.query).get('code')
    
    if not code:
        print("Error: Could not find 'code' in the URL you pasted.")
        return

    # 4. Exchange Code for Refresh Token
    token_url = f"{ISSUER}/v1/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code[0],
        "code_verifier": verifier
    }

    response = requests.post(token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        tokens = response.json()
        print("\nSUCCESS! HERE IS YOUR REFRESH TOKEN:")
        print("---------------------------------------------------")
        print(tokens.get('refresh_token'))
        print("---------------------------------------------------")
        print("Save this string! You can now use it in your scripts forever.")
    else:
        print(f"Error getting token: {response.text}")



if __name__ == "__main__":
    token = get_tokens()