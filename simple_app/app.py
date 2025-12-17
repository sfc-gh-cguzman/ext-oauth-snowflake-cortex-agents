"""
Customer's FastAPI Application - Separate Okta App

This demonstrates the multi-application OAuth pattern where:
- This is a DIFFERENT Okta application (different CLIENT_ID/SECRET)
- But uses the SAME Authorization Server as the original app
- Tokens from this app work with Snowflake because they trust the auth server
- Customer can build their own app and integrate Snowflake seamlessly!

Key Point: Snowflake trusts the AUTHORIZATION SERVER, not the specific client app.
"""

from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from urllib.parse import urlencode
import secrets
import hashlib
import base64
import requests
import snowflake.connector as sc
from typing import Optional, Dict
import uuid
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- CONFIGURATION ---
# Okta OAuth Configuration
OKTA_ISSUER = os.getenv("OKTA_ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
SCOPE = os.getenv("SCOPE")

# Snowflake Configuration
SNOWFLAKE_ACCOUNT = os.getenv("SNOWFLAKE_ACCOUNT")
SNOWFLAKE_WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE")
SNOWFLAKE_DATABASE = os.getenv("SNOWFLAKE_DATABASE")
SNOWFLAKE_SCHEMA = os.getenv("SNOWFLAKE_SCHEMA")

# Cortex Analyst Configuration
SEMANTIC_MODEL = os.getenv("SEMANTIC_MODEL")

# Application Configuration
APP_PORT = int(os.getenv("APP_PORT", "8001"))

# Initialize FastAPI
app = FastAPI(title="Customer App - Okta SSO with Snowflake")

# In-memory session store (use Redis/database in production)
oauth_sessions: Dict[str, dict] = {}  # state -> session data
user_sessions: Dict[str, dict] = {}  # session_id -> user data

def cleanup_old_sessions():
    """Clean up sessions older than 1 hour"""
    import time
    current_time = time.time()
    # Clean OAuth sessions (only need to last through the flow - 10 minutes)
    expired = [k for k, v in oauth_sessions.items() if current_time - v.get('created', 0) > 600]
    for k in expired:
        del oauth_sessions[k]
    # Clean user sessions (1 hour)
    expired = [k for k, v in user_sessions.items() if current_time - v.get('created', 0) > 3600]
    for k in expired:
        del user_sessions[k]

# --- HELPER FUNCTIONS ---

def generate_pkce():
    """Generate PKCE code verifier and challenge"""
    code_verifier = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')
    return code_verifier, code_challenge

def exchange_code_for_tokens(code: str, code_verifier: str):
    """Exchange authorization code for tokens"""
    token_url = f"{OKTA_ISSUER}/v1/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier
    }
    
    response = requests.post(token_url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Token exchange failed: {response.text}")

def refresh_access_token(refresh_token: str):
    """Get new access token using refresh token"""
    url = f"{OKTA_ISSUER}/v1/token"
    
    auth_str = f"{CLIENT_ID}:{CLIENT_SECRET}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Token refresh failed: {response.text}")

def get_user_info(access_token: str):
    """Get user info from Okta"""
    userinfo_url = f"{OKTA_ISSUER}/v1/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(userinfo_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def get_session_id(request: Request) -> Optional[str]:
    """Get session ID from cookie"""
    return request.cookies.get("session_id")

def get_session_data(session_id: str) -> Optional[dict]:
    """Get session data from server-side store"""
    if not session_id:
        return None
    return user_sessions.get(session_id)

def get_current_user(request: Request):
    """Dependency to get current authenticated user"""
    session_id = get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated - no session")
    
    session_data = get_session_data(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Not authenticated - session expired")
    
    user = session_data.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated - no user data")
    return user

def get_access_token(request: Request):
    """Dependency to get current access token"""
    session_id = get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")
    
    session_data = get_session_data(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Session expired")
    
    token = session_data.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No access token")
    return token

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page - shows login or user info"""
    session_id = get_session_id(request)
    session_data = get_session_data(session_id) if session_id else None
    user = session_data.get("user") if session_data else None
    
    if user:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Customer App - Okta SSO</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 900px;
                    margin: 50px auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                }}
                .container {{
                    background: rgba(255, 255, 255, 0.95);
                    padding: 40px;
                    border-radius: 10px;
                    color: #333;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                }}
                h1 {{ color: #f5576c; margin-top: 0; }}
                .user-info {{
                    background: #fff5f7;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                    border-left: 4px solid #f5576c;
                }}
                .info-box {{
                    background: #e8f4fd;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                    border-left: 4px solid #3498db;
                }}
                .btn {{
                    display: inline-block;
                    padding: 12px 24px;
                    margin: 10px 5px;
                    background: #f5576c;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    border: none;
                    cursor: pointer;
                    font-size: 16px;
                    transition: background 0.3s;
                }}
                .btn:hover {{ background: #e04560; }}
                .btn-secondary {{ background: #48bb78; }}
                .btn-secondary:hover {{ background: #38a169; }}
                .btn-info {{ background: #3498db; }}
                .btn-info:hover {{ background: #2980b9; }}
                .btn-danger {{ background: #e74c3c; }}
                .btn-danger:hover {{ background: #c0392b; }}
                code {{ 
                    background: #f4f4f4; 
                    padding: 2px 6px; 
                    border-radius: 3px;
                    color: #e74c3c;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎯 Customer Application</h1>
                <div class="user-info">
                    <p><strong>👤 User:</strong> {user.get('name', 'User')}</p>
                    <p><strong>📧 Email:</strong> {user.get('email', 'N/A')}</p>
                    <p><strong>✅ Status:</strong> Authenticated with Okta</p>
                    <p><strong>🔑 Client:</strong> Customer App (Different Okta App)</p>
                </div>
                
                <div class="info-box">
                    <h3>🌟 What Makes This Special?</h3>
                    <p>This is a <strong>SEPARATE Okta application</strong> from the original demo, but:</p>
                    <ul>
                        <li>✅ Uses the <strong>SAME Authorization Server</strong></li>
                        <li>✅ Tokens work with <strong>Snowflake automatically</strong></li>
                        <li>✅ No additional Snowflake configuration needed</li>
                        <li>✅ Demonstrates the multi-app OAuth pattern</li>
                    </ul>
                    <p><small>📝 This simulates a customer building their own app while using your OAuth infrastructure!</small></p>
                </div>
                
                <h2>🔗 Available Actions</h2>
                <p>Test the integration with these endpoints:</p>
                
                <a href="/chat" class="btn" style="background: #9b59b6; font-size: 18px; padding: 15px 30px;">🤖 Open Cortex Analyst Chat</a>
                <br><br>
                <a href="/api/user" class="btn btn-info">📋 View User Info (JSON)</a>
                <a href="/api/snowflake/test" class="btn btn-secondary">❄️ Test Snowflake Connection</a>
                <a href="/api/snowflake/query" class="btn btn-secondary">📊 Query Snowflake</a>
                <a href="/api/compare" class="btn">🔍 Compare Apps</a>
                <br>
                <a href="/logout" class="btn btn-danger">🚪 Logout</a>
                
                <h2>💡 Architecture</h2>
                <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <pre style="margin: 0; color: #333; overflow-x: auto;">
Customer App (Port 8001, Client ID: 0oayeyt...)
    ↓
SAME Auth Server (ausydcly58VvRhnAx697)
    ↓
OAuth Token (Valid for Snowflake!)
    ↓
Snowflake validates via trusted auth server
    ↓
✅ Access Granted
                    </pre>
                </div>
                
                <h2>🎓 Key Concept</h2>
                <p>Snowflake trusts the <strong>Authorization Server</strong>, not specific client applications.</p>
                <p>This means:</p>
                <ul>
                    <li>Multiple customer apps can share the same OAuth integration</li>
                    <li>Each app has its own credentials (security isolation)</li>
                    <li>All apps get tokens that work with Snowflake</li>
                    <li>Centralized access control via auth server</li>
                </ul>
            </div>
        </body>
        </html>
        """
    else:
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Customer App - Okta SSO</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 700px;
                    margin: 100px auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    text-align: center;
                }
                .container {
                    background: white;
                    padding: 50px;
                    border-radius: 10px;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                }
                h1 { color: #f5576c; margin-bottom: 20px; }
                .subtitle { 
                    color: #666; 
                    font-size: 18px;
                    margin-bottom: 30px;
                }
                .info-box {
                    background: #e8f4fd;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 30px 0;
                    text-align: left;
                }
                .btn {
                    display: inline-block;
                    padding: 15px 40px;
                    background: #f5576c;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 18px;
                    transition: background 0.3s;
                    margin-top: 20px;
                }
                .btn:hover { background: #e04560; }
                p { color: #666; line-height: 1.6; }
                code {
                    background: #f4f4f4;
                    padding: 2px 6px;
                    border-radius: 3px;
                    color: #e74c3c;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎯 Customer Application</h1>
                <p class="subtitle">Separate Okta App • Shared Authorization Server</p>
                
                <div class="info-box">
                    <h3>🌟 What is this?</h3>
                    <p>This demonstrates the <strong>multi-application OAuth pattern</strong>:</p>
                    <ul>
                        <li>This is a <strong>different</strong> Okta application</li>
                        <li>Uses the <strong>same</strong> Authorization Server</li>
                        <li>Tokens work with <strong>Snowflake</strong> automatically</li>
                    </ul>
                    <p><small>Running on port <code>8001</code> with client ID <code>0oayeyt...</code></small></p>
                </div>
                
                <p>Login once, access everything!</p>
                <a href="/login" class="btn">Login with Okta</a>
            </div>
        </body>
        </html>
        """
    
    return HTMLResponse(content=html_content)

@app.get("/login")
async def login(request: Request):
    """Initiate OAuth login flow"""
    import time
    
    # Clean up old sessions
    cleanup_old_sessions()
    
    # Generate PKCE
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    
    # Store OAuth session data in server-side store (keyed by state)
    oauth_sessions[state] = {
        "code_verifier": code_verifier,
        "state": state,
        "created": time.time()
    }
    
    # Debug logging
    print(f"🎯 Customer App - Generated state: {state}")
    print(f"🎯 Customer App - Client ID: {CLIENT_ID}")
    print(f"🎯 Customer App - Auth Server: {OKTA_ISSUER}")
    print(f"🎯 Customer App - Total OAuth sessions: {len(oauth_sessions)}")
    
    # Build authorization URL with proper encoding
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPE,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"{OKTA_ISSUER}/v1/authorize?{urlencode(params)}"
    
    print(f"🔗 Redirecting to: {auth_url[:100]}...")
    
    return RedirectResponse(url=auth_url, status_code=302)

@app.get("/callback")
async def callback(code: str, state: str):
    """Handle OAuth callback"""
    import time
    
    # Debug logging
    print(f"🎯 Customer App - Callback received")
    print(f"🔍 Callback - Received state: {state}")
    
    # Retrieve OAuth session data from server-side store
    oauth_session = oauth_sessions.get(state)
    
    if not oauth_session:
        print(f"❌ Callback - State not found in server memory!")
        raise HTTPException(
            status_code=400, 
            detail="Session expired or invalid. Please try logging in again."
        )
    
    print(f"✅ Callback - Found OAuth session")
    
    # Verify state matches (CSRF protection)
    if state != oauth_session.get("state"):
        raise HTTPException(
            status_code=400, 
            detail="State mismatch - possible CSRF attack"
        )
    
    # Exchange code for tokens
    code_verifier = oauth_session.get("code_verifier")
    try:
        print(f"🔄 Exchanging code for tokens...")
        tokens = exchange_code_for_tokens(code, code_verifier)
        
        print(f"✅ Got tokens from auth server, fetching user info...")
        # Get user info
        user_info = get_user_info(tokens.get("access_token"))
        
        # Create new user session
        session_id = str(uuid.uuid4())
        user_sessions[session_id] = {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
            "id_token": tokens.get("id_token"),
            "user": user_info,
            "created": time.time(),
            "client_id": CLIENT_ID  # Store which app issued this session
        }
        
        print(f"✅ Created user session: {session_id}")
        print(f"🎉 Customer App authentication complete!")
        
        # Clean up OAuth session (no longer needed)
        del oauth_sessions[state]
        
        # Set session cookie and redirect
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=3600,  # 1 hour
            httponly=True,
            samesite="lax"
        )
        
        return response
    
    except Exception as e:
        print(f"❌ Authentication failed: {str(e)}")
        # Clean up OAuth session on error
        if state in oauth_sessions:
            del oauth_sessions[state]
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")

@app.get("/logout")
async def logout(request: Request):
    """Logout user"""
    session_id = get_session_id(request)
    if session_id and session_id in user_sessions:
        del user_sessions[session_id]
        print(f"🚪 Customer App - Logged out session: {session_id}")
    
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session_id")
    return response

@app.get("/api/user")
async def api_user_info(user: dict = Depends(get_current_user)):
    """Get current user info (JSON)"""
    return JSONResponse(content=user)

@app.get("/api/compare")
async def api_compare(request: Request, user: dict = Depends(get_current_user)):
    """Compare this app with the original app"""
    session_id = get_session_id(request)
    session_data = get_session_data(session_id)
    
    return JSONResponse(content={
        "message": "Multi-Application OAuth Pattern",
        "this_app": {
            "name": "Customer Application",
            "client_id": CLIENT_ID,
            "port": 8001,
            "description": "Separate Okta application"
        },
        "original_app": {
            "name": "Original Demo App",
            "client_id": "0oaydca2igUSmWSjO697",
            "port": 8000,
            "description": "First Okta application"
        },
        "shared": {
            "authorization_server": OKTA_ISSUER,
            "snowflake_account": SNOWFLAKE_ACCOUNT,
            "key_point": "Both apps use the same auth server, so tokens work with Snowflake!"
        },
        "current_session": {
            "user_email": user.get("email"),
            "authenticated_via": "Customer App (0oayeyt...)"
        }
    })

@app.get("/api/token/refresh")
async def api_refresh_token(request: Request):
    """Refresh access token"""
    session_id = get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")
    
    session_data = get_session_data(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Session expired")
    
    refresh_token = session_data.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token available")
    
    try:
        new_tokens = refresh_access_token(refresh_token)
        
        # Update session data
        session_data["access_token"] = new_tokens.get("access_token")
        if "refresh_token" in new_tokens:
            session_data["refresh_token"] = new_tokens.get("refresh_token")
        
        user_sessions[session_id] = session_data
        
        return JSONResponse(content={"message": "Token refreshed successfully"})
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token refresh failed: {str(e)}")

@app.get("/api/snowflake/test")
async def api_snowflake_test(
    request: Request,
    user: dict = Depends(get_current_user),
    access_token: str = Depends(get_access_token)
):
    """Test Snowflake connection with OAuth token from Customer App"""
    try:
        print(f"🎯 Customer App - Testing Snowflake connection...")
        print(f"🔑 Using token from Customer App (Client: {CLIENT_ID})")
        
        conn_params = {
            'account': SNOWFLAKE_ACCOUNT,
            'user': user.get('email', 'unknown'),
            'authenticator': 'oauth',
            'token': access_token,
            'warehouse': SNOWFLAKE_WAREHOUSE,
            'database': SNOWFLAKE_DATABASE,
            'schema': SNOWFLAKE_SCHEMA
        }
        
        ctx = sc.connect(**conn_params)
        cs = ctx.cursor()
        
        cs.execute("SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_DATABASE(), CURRENT_SCHEMA(), CURRENT_TIMESTAMP()")
        result = cs.fetchone()
        
        cs.close()
        ctx.close()
        
        print(f"✅ Snowflake connection successful from Customer App!")
        
        return JSONResponse(content={
            "success": True,
            "message": "Snowflake connection successful from Customer App!",
            "authenticated_via": "Customer App (0oayeyt...)",
            "key_point": "Token from different Okta app works because of shared auth server!",
            "data": {
                "user": result[0],
                "role": result[1],
                "database": result[2],
                "schema": result[3],
                "timestamp": str(result[4])
            }
        })
    
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Snowflake connection failed: {error_msg}")
        # Check if token expired
        if "token" in error_msg.lower() or "expired" in error_msg.lower():
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "error": "Token expired. Try refreshing: /api/token/refresh"
                }
            )
        raise HTTPException(status_code=500, detail=f"Snowflake error: {error_msg}")

@app.get("/api/snowflake/query")
async def api_snowflake_query(
    request: Request,
    query: str = "SHOW TABLES LIMIT 5",
    user: dict = Depends(get_current_user),
    access_token: str = Depends(get_access_token)
):
    """Execute custom Snowflake query"""
    try:
        conn_params = {
            'account': SNOWFLAKE_ACCOUNT,
            'user': user.get('email', 'unknown'),
            'authenticator': 'oauth',
            'token': access_token,
            'warehouse': SNOWFLAKE_WAREHOUSE,
            'database': SNOWFLAKE_DATABASE,
            'schema': SNOWFLAKE_SCHEMA
        }
        
        ctx = sc.connect(**conn_params)
        cs = ctx.cursor()
        
        cs.execute(query)
        results = cs.fetchall()
        columns = [desc[0] for desc in cs.description]
        
        cs.close()
        ctx.close()
        
        # Format results
        formatted_results = []
        for row in results:
            formatted_results.append(dict(zip(columns, [str(v) for v in row])))
        
        return JSONResponse(content={
            "success": True,
            "query": query,
            "row_count": len(results),
            "columns": columns,
            "data": formatted_results,
            "authenticated_via": "Customer App (0oayeyt...)"
        })
    
    except Exception as e:
        error_msg = str(e)
        if "token" in error_msg.lower() or "expired" in error_msg.lower():
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "error": "Token expired. Try refreshing: /api/token/refresh"
                }
            )
        raise HTTPException(status_code=500, detail=f"Query error: {error_msg}")

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "message": "Customer App running",
        "app": "customer_app",
        "port": 8001,
        "client_id": CLIENT_ID[:12] + "..."
    }

# =============================================================================
# CORTEX ANALYST CHATBOT INTERFACE
# =============================================================================

@app.get("/chat", response_class=HTMLResponse)
async def chat_interface(request: Request):
    """Cortex Analyst Chat Interface"""
    session_id = get_session_id(request)
    session_data = get_session_data(session_id) if session_id else None
    user = session_data.get("user") if session_data else None
    
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cortex Analyst Chat</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                height: 100vh;
                display: flex;
                flex-direction: column;
            }}
            .header {{
                background: white;
                padding: 15px 30px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .header h1 {{
                color: #f5576c;
                font-size: 24px;
            }}
            .header .user-info {{
                color: #666;
                font-size: 14px;
            }}
            .header .btn {{
                padding: 8px 16px;
                background: #f5576c;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                margin-left: 10px;
            }}
            .chat-container {{
                flex: 1;
                max-width: 1200px;
                width: 100%;
                margin: 20px auto;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }}
            .chat-header {{
                background: #f5576c;
                color: white;
                padding: 15px 20px;
                border-bottom: 1px solid #e04560;
            }}
            .chat-messages {{
                flex: 1;
                overflow-y: auto;
                padding: 20px;
                background: #f9f9f9;
            }}
            .message {{
                margin-bottom: 15px;
                display: flex;
                flex-direction: column;
            }}
            .message.user {{
                align-items: flex-end;
            }}
            .message.analyst {{
                align-items: flex-start;
            }}
            .message-content {{
                max-width: 70%;
                padding: 12px 16px;
                border-radius: 10px;
                word-wrap: break-word;
            }}
            .message.user .message-content {{
                background: #f5576c;
                color: white;
            }}
            .message.analyst .message-content {{
                background: white;
                color: #333;
                border: 1px solid #ddd;
            }}
            .message-label {{
                font-size: 12px;
                color: #666;
                margin-bottom: 5px;
                font-weight: 500;
            }}
            .sql-container {{
                background: #2d2d2d;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 5px;
                margin: 10px 0;
                overflow-x: auto;
                font-family: 'Courier New', monospace;
                font-size: 13px;
            }}
            .sql-header {{
                color: #a6e22e;
                font-weight: bold;
                margin-bottom: 10px;
            }}
            .results-table {{
                width: 100%;
                border-collapse: collapse;
                margin: 10px 0;
                background: white;
                font-size: 13px;
            }}
            .results-table th {{
                background: #f5576c;
                color: white;
                padding: 10px;
                text-align: left;
                font-weight: 600;
            }}
            .results-table td {{
                padding: 8px 10px;
                border-bottom: 1px solid #ddd;
            }}
            .results-table tr:hover {{
                background: #f9f9f9;
            }}
            .loading {{
                text-align: center;
                padding: 20px;
                color: #666;
            }}
            .spinner {{
                border: 3px solid #f3f3f3;
                border-top: 3px solid #f5576c;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            .chat-input-container {{
                padding: 20px;
                background: white;
                border-top: 1px solid #ddd;
                display: flex;
                gap: 10px;
            }}
            .chat-input {{
                flex: 1;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }}
            .chat-input:focus {{
                outline: none;
                border-color: #f5576c;
            }}
            .send-btn {{
                padding: 12px 30px;
                background: #f5576c;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
            }}
            .send-btn:hover {{
                background: #e04560;
            }}
            .send-btn:disabled {{
                background: #ccc;
                cursor: not-allowed;
            }}
            .error {{
                background: #fee;
                border: 1px solid #fcc;
                color: #c00;
                padding: 12px;
                border-radius: 5px;
                margin: 10px 0;
            }}
            .warning {{
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
                padding: 12px;
                border-radius: 5px;
                margin: 10px 0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🤖 Cortex Analyst Chat</h1>
                <div class="user-info">Authenticated as: {user.get('email', 'User')}</div>
            </div>
            <div>
                <a href="/" class="btn">← Back to Dashboard</a>
                <a href="/logout" class="btn">Logout</a>
            </div>
        </div>
        
        <div class="chat-container">
            <div class="chat-header">
                <h2>💬 Ask questions about your data in natural language</h2>
                <p style="margin-top: 5px; font-size: 14px; opacity: 0.9;">
                    Using OAuth token from Customer App • Powered by Cortex Analyst
                </p>
            </div>
            
            <div class="chat-messages" id="chatMessages">
                <div class="message analyst">
                    <div class="message-label">Cortex Analyst</div>
                    <div class="message-content">
                        👋 Hello! I'm Cortex Analyst. Ask me anything about your data, and I'll generate SQL queries and visualize the results for you.
                        <br><br>
                        Try asking: "What questions can I ask?" or "Show me recent data"
                    </div>
                </div>
            </div>
            
            <div class="chat-input-container">
                <input 
                    type="text" 
                    class="chat-input" 
                    id="messageInput" 
                    placeholder="Type your question here..."
                    autocomplete="off"
                />
                <button class="send-btn" id="sendBtn" onclick="sendMessage()">
                    Send
                </button>
            </div>
        </div>
        
        <script>
            let conversationHistory = [];
            
            // Allow Enter key to send message
            document.getElementById('messageInput').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter' && !e.shiftKey) {{
                    e.preventDefault();
                    sendMessage();
                }}
            }});
            
            function scrollToBottom() {{
                const messages = document.getElementById('chatMessages');
                messages.scrollTop = messages.scrollHeight;
            }}
            
            function addMessage(role, content, isHtml = false) {{
                const messagesDiv = document.getElementById('chatMessages');
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${{role}}`;
                
                const label = document.createElement('div');
                label.className = 'message-label';
                label.textContent = role === 'user' ? 'You' : 'Cortex Analyst';
                
                const contentDiv = document.createElement('div');
                contentDiv.className = 'message-content';
                
                if (isHtml) {{
                    contentDiv.innerHTML = content;
                }} else {{
                    contentDiv.textContent = content;
                }}
                
                messageDiv.appendChild(label);
                messageDiv.appendChild(contentDiv);
                messagesDiv.appendChild(messageDiv);
                
                scrollToBottom();
            }}
            
            function addLoadingMessage() {{
                const messagesDiv = document.getElementById('chatMessages');
                const loadingDiv = document.createElement('div');
                loadingDiv.id = 'loadingMessage';
                loadingDiv.className = 'message analyst';
                loadingDiv.innerHTML = `
                    <div class="message-label">Cortex Analyst</div>
                    <div class="message-content">
                        <div class="loading">
                            <div class="spinner"></div>
                            <p style="margin-top: 10px;">Thinking...</p>
                        </div>
                    </div>
                `;
                messagesDiv.appendChild(loadingDiv);
                scrollToBottom();
            }}
            
            function removeLoadingMessage() {{
                const loading = document.getElementById('loadingMessage');
                if (loading) loading.remove();
            }}
            
            function formatSqlResults(data) {{
                if (!data || data.length === 0) return '<p>No results returned</p>';
                
                const columns = Object.keys(data[0]);
                let html = '<table class="results-table"><thead><tr>';
                
                columns.forEach(col => {{
                    html += `<th>${{col}}</th>`;
                }});
                html += '</tr></thead><tbody>';
                
                data.forEach(row => {{
                    html += '<tr>';
                    columns.forEach(col => {{
                        html += `<td>${{row[col] !== null ? row[col] : 'NULL'}}</td>`;
                    }});
                    html += '</tr>';
                }});
                
                html += '</tbody></table>';
                return html;
            }}
            
            async function sendMessage() {{
                const input = document.getElementById('messageInput');
                const sendBtn = document.getElementById('sendBtn');
                const message = input.value.trim();
                
                if (!message) return;
                
                // Disable input
                input.disabled = true;
                sendBtn.disabled = true;
                
                // Add user message
                addMessage('user', message);
                conversationHistory.push({{
                    role: 'user',
                    content: [{{ type: 'text', text: message }}]
                }});
                
                // Clear input
                input.value = '';
                
                // Show loading
                addLoadingMessage();
                
                try {{
                    const response = await fetch('/api/cortex/chat', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            messages: conversationHistory
                        }})
                    }});
                    
                    const data = await response.json();
                    removeLoadingMessage();
                    
                    if (!response.ok) {{
                        addMessage('analyst', `Error: ${{data.detail || 'Failed to get response'}}`, true);
                        return;
                    }}
                    
                    // Add analyst response to history
                    conversationHistory.push({{
                        role: 'analyst',
                        content: data.content
                    }});
                    
                    // Display the response
                    let htmlContent = '';
                    
                    for (const item of data.content) {{
                        if (item.type === 'text') {{
                            htmlContent += `<p>${{item.text}}</p>`;
                        }} else if (item.type === 'sql') {{
                            htmlContent += `
                                <div class="sql-container">
                                    <div class="sql-header">📊 Generated SQL Query:</div>
                                    <pre>${{item.statement}}</pre>
                                </div>
                            `;
                            
                            if (item.results) {{
                                htmlContent += '<div style="margin-top: 15px;"><strong>Results:</strong></div>';
                                htmlContent += formatSqlResults(item.results);
                            }}
                        }} else if (item.type === 'suggestions') {{
                            htmlContent += '<div style="margin-top: 10px;"><strong>💡 Suggestions:</strong><ul>';
                            item.suggestions.forEach(s => {{
                                htmlContent += `<li>${{s}}</li>`;
                            }});
                            htmlContent += '</ul></div>';
                        }}
                    }}
                    
                    if (data.warnings && data.warnings.length > 0) {{
                        htmlContent += '<div class="warning">';
                        data.warnings.forEach(w => {{
                            htmlContent += `⚠️ ${{w.message}}<br>`;
                        }});
                        htmlContent += '</div>';
                    }}
                    
                    addMessage('analyst', htmlContent, true);
                    
                }} catch (error) {{
                    removeLoadingMessage();
                    addMessage('analyst', `Error: ${{error.message}}`, true);
                }} finally {{
                    // Re-enable input
                    input.disabled = false;
                    sendBtn.disabled = false;
                    input.focus();
                }}
            }}
            
            // Focus input on load
            document.getElementById('messageInput').focus();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/api/cortex/chat")
async def cortex_chat(
    request: Request,
    user: dict = Depends(get_current_user),
    access_token: str = Depends(get_access_token)
):
    """
    Cortex Analyst chat endpoint - processes natural language queries
    """
    try:
        body = await request.json()
        messages = body.get("messages", [])
        
        if not messages:
            raise HTTPException(status_code=400, detail="No messages provided")
        
        print(f"🤖 Cortex Analyst - Processing query for user: {user.get('email')}")
        print(f"🔑 Using OAuth token from Customer App")
        
        # First, establish a Snowflake connection to get the proper REST token
        # The Cortex API requires the connection's REST token, not the raw OAuth token
        conn_params = {
            'account': SNOWFLAKE_ACCOUNT,
            'user': user.get('email', 'unknown'),
            'authenticator': 'oauth',
            'token': access_token,
            'warehouse': SNOWFLAKE_WAREHOUSE,
            'database': SNOWFLAKE_DATABASE,
            'schema': SNOWFLAKE_SCHEMA
        }
        
        print(f"🔗 Establishing Snowflake connection...")
        try:
            conn = sc.connect(**conn_params)
        except Exception as e:
            print(f"❌ Failed to establish Snowflake connection: {str(e)}")
            raise HTTPException(
                status_code=401,
                detail=f"Could not connect to Snowflake. Your session may have expired. Please logout and login again."
            )
        
        # Extract the REST token from the connection
        # This is the token format that Cortex Analyst expects
        rest_token = conn.rest.token
        print(f"✅ Got REST token from connection")
        
        # Build Cortex Analyst API endpoint
        # Replace underscores with hyphens in account identifier for API host
        host = conn.host.replace('_', '-')
        cortex_url = f"https://{host}/api/v2/cortex/analyst/message"
        
        print(f"📡 Cortex API URL: {cortex_url}")
        
        # Prepare request to Cortex Analyst using the REST token
        headers = {
            "Authorization": f'Snowflake Token="{rest_token}"',
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Prepare request body with semantic model
        request_body = {
            "messages": messages,
            "semantic_models": [{"semantic_view": SEMANTIC_MODEL}]
        }
        
        print(f"📤 Sending request to Cortex Analyst...")
        
        # Call Cortex Analyst API
        response = requests.post(
            cortex_url,
            headers=headers,
            json=request_body,
            timeout=60
        )
        
        print(f"📥 Response status: {response.status_code}")
        
        if response.status_code != 200:
            error_data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"❌ Cortex API error: {error_data}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Cortex Analyst error: {error_data.get('message', response.text)}"
            )
        
        analyst_response = response.json()
        content = analyst_response.get("message", {}).get("content", [])
        warnings = analyst_response.get("warnings", [])
        
        # Execute SQL queries if present in the response
        # Reuse the same connection we already established
        for item in content:
            if item.get("type") == "sql":
                sql_query = item.get("statement")
                if sql_query:
                    try:
                        print(f"🔍 Executing SQL query...")
                        
                        # Use the existing connection
                        cs = conn.cursor()
                        cs.execute(sql_query)
                        
                        # Fetch results
                        results = cs.fetchall()
                        columns = [desc[0] for desc in cs.description]
                        
                        # Format results as list of dicts
                        formatted_results = []
                        for row in results[:100]:  # Limit to 100 rows for display
                            formatted_results.append(dict(zip(columns, [str(v) if v is not None else None for v in row])))
                        
                        item["results"] = formatted_results
                        item["row_count"] = len(results)
                        
                        cs.close()
                        
                        print(f"✅ Query executed successfully: {len(results)} rows")
                        
                    except Exception as e:
                        print(f"❌ SQL execution error: {str(e)}")
                        item["error"] = str(e)
        
        # Close the connection
        conn.close()
        print(f"🎉 Cortex Analyst response complete")
        
        return JSONResponse(content={
            "content": content,
            "warnings": warnings,
            "request_id": analyst_response.get("request_id")
        })
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Cortex chat error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print("🎯 Starting Customer Application (Separate Okta App)...")
    print(f"📍 Navigate to: http://localhost:{APP_PORT}")
    print(f"🔑 Client ID: {CLIENT_ID}")
    print(f"🔐 Auth Server: {OKTA_ISSUER}")
    print("💡 This app uses a DIFFERENT Okta app but SAME auth server!")
    print("🚀 Tokens from this app will work with Snowflake!")
    print(f"🤖 Cortex Analyst chat available at: http://localhost:{APP_PORT}/chat")
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)

