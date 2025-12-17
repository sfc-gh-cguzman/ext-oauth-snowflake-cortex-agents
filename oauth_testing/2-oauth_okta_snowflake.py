import requests
import base64
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- CONFIGURATION ---
OKTA_ISSUER = os.getenv("OKTA_ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

def get_token_from_refresh():
    url = f"{OKTA_ISSUER}/v1/token"
    
    # Basic Auth header (Client ID + Secret)
    auth_str = f"{CLIENT_ID}:{CLIENT_SECRET}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    
    data = {
        "grant_type": "refresh_token",
        "refresh_token": REFRESH_TOKEN,
        # Scope is optional here; it will grant the same scopes as the original token
    }
    
    response = requests.post(url, headers=headers, data=data)
    
    if response.status_code == 200:
        new_tokens = response.json()
        print("Success! New Access Token:")
        print(new_tokens.get("access_token"))
        
        # NOTE: Okta might return a NEW refresh token. If so, update your storage!
        if "refresh_token" in new_tokens:
            print("\nWARNING: Okta rotated your refresh token. Save this new one for next time:")
            print(new_tokens.get("refresh_token"))
    else:
        print(f"Error: {response.status_code} - {response.text}")

get_token_from_refresh()