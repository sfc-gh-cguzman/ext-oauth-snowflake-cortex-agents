"""
Cortex Agent Application - FastAPI with Streaming Chat

This demonstrates:
- Same OAuth authentication as customer_app
- Cortex Agents API integration with streaming (SSE)
- Agent selection from available agents in account
- Collapsible message history
- Real-time streaming responses
"""

from fastapi import FastAPI, Request, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from urllib.parse import urlencode, quote
import secrets
import hashlib
import base64
import requests
import snowflake.connector as sc
from typing import Optional, Dict
import uuid
import json
import asyncio
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

# Application Configuration
APP_PORT = int(os.getenv("APP_PORT", "8002"))

# Initialize FastAPI
app = FastAPI(title="Cortex Agent Chat - Streaming")

# In-memory session store
oauth_sessions: Dict[str, dict] = {}
user_sessions: Dict[str, dict] = {}

def cleanup_old_sessions():
    """Clean up sessions older than 1 hour"""
    import time
    current_time = time.time()
    expired = [k for k, v in oauth_sessions.items() if current_time - v.get('created', 0) > 600]
    for k in expired:
        del oauth_sessions[k]
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

# --- SSE PARSING HELPERS ---

def parse_sse_block(lines: list) -> Optional[Dict]:
    """
    Parse an SSE block into event and data.
    Based on: https://github.com/sfc-gh-mwalli/CortexAgentStreamlit
    """
    event_type = None
    data_lines = []
    
    for line in lines:
        if line.startswith('event:'):
            event_type = line[len('event:'):].strip()
        elif line.startswith('data:'):
            data_lines.append(line[len('data:'):].lstrip())
    
    data_str = "\n".join(data_lines).strip()
    if not data_str:
        return None
    
    try:
        parsed = json.loads(data_str)
        if isinstance(parsed, dict):
            if event_type and "event" not in parsed:
                parsed["event"] = event_type
            return parsed
        else:
            return {"data": parsed, "event": event_type}
    except json.JSONDecodeError:
        return {"data": data_str, "event": event_type}


# --- AUTHENTICATION ROUTES ---

@app.get("/login")
async def login(request: Request):
    """Initiate OAuth login flow"""
    import time
    
    cleanup_old_sessions()
    
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    
    oauth_sessions[state] = {
        "code_verifier": code_verifier,
        "state": state,
        "created": time.time()
    }
    
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
    return RedirectResponse(url=auth_url, status_code=302)

@app.get("/callback")
async def callback(code: str, state: str):
    """Handle OAuth callback"""
    import time
    
    oauth_session = oauth_sessions.get(state)
    
    if not oauth_session:
        raise HTTPException(status_code=400, detail="Session expired or invalid. Please try logging in again.")
    
    if state != oauth_session.get("state"):
        raise HTTPException(status_code=400, detail="State mismatch - possible CSRF attack")
    
    code_verifier = oauth_session.get("code_verifier")
    try:
        tokens = exchange_code_for_tokens(code, code_verifier)
        user_info = get_user_info(tokens.get("access_token"))
        
        session_id = str(uuid.uuid4())
        user_sessions[session_id] = {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
            "id_token": tokens.get("id_token"),
            "user": user_info,
            "created": time.time(),
            "client_id": CLIENT_ID
        }
        
        del oauth_sessions[state]
        
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=3600,
            httponly=True,
            samesite="lax"
        )
        
        return response
    
    except Exception as e:
        if state in oauth_sessions:
            del oauth_sessions[state]
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")

@app.get("/logout")
async def logout(request: Request):
    """Logout user"""
    session_id = get_session_id(request)
    if session_id and session_id in user_sessions:
        del user_sessions[session_id]
    
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session_id")
    return response

# --- MAIN CHAT INTERFACE ---

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Landing page or main chat interface"""
    session_id = get_session_id(request)
    session_data = get_session_data(session_id) if session_id else None
    user = session_data.get("user") if session_data else None
    
    if not user:
        # Show landing page
        return landing_page()
    
    # Show chat interface if authenticated
    return chat_interface(user)

def landing_page():
    """Beautiful landing page for unauthenticated users"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cortex Agent Chat - Login</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .landing-container {
                max-width: 800px;
                width: 100%;
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                overflow: hidden;
            }
            .hero {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 60px 40px;
                text-align: center;
            }
            .hero h1 {
                font-size: 48px;
                margin-bottom: 20px;
                font-weight: 700;
            }
            .hero p {
                font-size: 20px;
                opacity: 0.95;
                line-height: 1.6;
            }
            .content {
                padding: 50px 40px;
            }
            .features {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
                margin-bottom: 40px;
            }
            .feature {
                display: flex;
                align-items: start;
                gap: 15px;
            }
            .feature-icon {
                font-size: 32px;
                flex-shrink: 0;
            }
            .feature-text h3 {
                font-size: 18px;
                color: #333;
                margin-bottom: 8px;
            }
            .feature-text p {
                font-size: 14px;
                color: #666;
                line-height: 1.5;
            }
            .cta {
                text-align: center;
                padding-top: 20px;
                border-top: 1px solid #e0e0e0;
            }
            .login-btn {
                display: inline-block;
                padding: 18px 50px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                text-decoration: none;
                border-radius: 50px;
                font-size: 18px;
                font-weight: 600;
                transition: transform 0.2s, box-shadow 0.2s;
                box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            }
            .login-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 30px rgba(102, 126, 234, 0.6);
            }
            .tech-stack {
                margin-top: 40px;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 10px;
                text-align: center;
            }
            .tech-stack h4 {
                font-size: 14px;
                color: #666;
                margin-bottom: 15px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .tech-badges {
                display: flex;
                justify-content: center;
                gap: 15px;
                flex-wrap: wrap;
            }
            .tech-badge {
                padding: 8px 16px;
                background: white;
                border: 2px solid #667eea;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
                color: #667eea;
            }
        </style>
    </head>
    <body>
        <div class="landing-container">
            <div class="hero">
                <h1>🤖 Cortex Agent Chat</h1>
                <p>AI-Powered Conversations with Your Snowflake Data</p>
            </div>
            
            <div class="content">
                <div class="features">
                    <div class="feature">
                        <div class="feature-icon">🔐</div>
                        <div class="feature-text">
                            <h3>Secure OAuth</h3>
                            <p>Enterprise-grade authentication via Okta with single sign-on</p>
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">🌊</div>
                        <div class="feature-text">
                            <h3>Real-time Streaming</h3>
                            <p>Watch responses appear in real-time with Server-Sent Events</p>
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">🎯</div>
                        <div class="feature-text">
                            <h3>Multi-Agent Support</h3>
                            <p>Select from all available Cortex Agents in your account</p>
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">🧠</div>
                        <div class="feature-text">
                            <h3>Thinking Process</h3>
                            <p>See how agents reason through problems in collapsible sections</p>
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">❄️</div>
                        <div class="feature-text">
                            <h3>Snowflake Integration</h3>
                            <p>Direct access to your data with Cortex AI capabilities</p>
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">💬</div>
                        <div class="feature-text">
                            <h3>Conversational AI</h3>
                            <p>Natural language interface for complex data tasks</p>
                        </div>
                    </div>
                </div>
                
                <div class="cta">
                    <a href="/login" class="login-btn">Login with Okta</a>
                    <p style="margin-top: 20px; color: #999; font-size: 14px;">
                        Login once, access all Cortex Agents
                    </p>
                </div>
                
                <div class="tech-stack">
                    <h4>Powered By</h4>
                    <div class="tech-badges">
                        <span class="tech-badge">FastAPI</span>
                        <span class="tech-badge">Okta OAuth</span>
                        <span class="tech-badge">Snowflake Cortex</span>
                        <span class="tech-badge">SSE Streaming</span>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

def chat_interface(user: dict):
    """Chat interface for authenticated users"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cortex Agent Chat</title>
        <!-- Vega-Lite for chart rendering -->
        <script src="https://cdn.jsdelivr.net/npm/vega@5"></script>
        <script src="https://cdn.jsdelivr.net/npm/vega-lite@5"></script>
        <script src="https://cdn.jsdelivr.net/npm/vega-embed@6"></script>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                height: 100vh;
                display: flex;
                flex-direction: column;
                background: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .header h1 {{
                font-size: 24px;
                font-weight: 600;
            }}
            .header .user-info {{
                font-size: 14px;
                opacity: 0.9;
            }}
            .header .btn {{
                padding: 8px 16px;
                background: rgba(255,255,255,0.2);
                color: white;
                text-decoration: none;
                border-radius: 4px;
                margin-left: 10px;
                transition: background 0.2s;
            }}
            .header .btn:hover {{
                background: rgba(255,255,255,0.3);
            }}
            .main-container {{
                flex: 1;
                display: flex;
                overflow: hidden;
            }}
            .sidebar {{
                width: 320px;
                background: white;
                border-right: 1px solid #e0e0e0;
                display: flex;
                flex-direction: column;
                overflow: hidden;
                flex-shrink: 0;
            }}
            .sidebar-header {{
                padding: 20px;
                border-bottom: 1px solid #e0e0e0;
                background: #fafafa;
            }}
            .sidebar-header h2 {{
                font-size: 16px;
                color: #333;
                margin-bottom: 15px;
            }}
            .agent-selector-label {{
                font-size: 13px;
                font-weight: 600;
                color: #555;
                margin-bottom: 8px;
                display: block;
            }}
            .agent-select {{
                width: 100%;
                padding: 10px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                font-size: 13px;
                font-family: inherit;
                background: white;
                cursor: pointer;
                margin-bottom: 15px;
            }}
            .agent-select:focus {{
                outline: none;
                border-color: #667eea;
            }}
            .clear-btn {{
                width: 100%;
                padding: 12px;
                background: #e74c3c;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
            }}
            .clear-btn:hover {{
                background: #c0392b;
            }}
            .clear-btn:disabled {{
                background: #ccc;
                cursor: not-allowed;
            }}
            .sidebar-info {{
                padding: 20px;
                flex: 1;
                overflow-y: auto;
            }}
            .info-card {{
                background: #f9f9f9;
                padding: 15px;
                border-radius: 5px;
                border-left: 3px solid #667eea;
                margin-bottom: 15px;
            }}
            .info-card h3 {{
                font-size: 14px;
                color: #333;
                margin-bottom: 8px;
            }}
            .info-card p {{
                font-size: 12px;
                color: #666;
                line-height: 1.5;
                margin: 0;
            }}
            .info-label {{
                font-weight: 600;
                color: #667eea;
            }}
            .chat-area {{
                flex: 1;
                display: flex;
                flex-direction: column;
                background: white;
                overflow: hidden;
            }}
            .chat-messages {{
                flex: 1;
                overflow-y: auto;
                overflow-x: hidden;
                padding: 20px;
                background: #fafafa;
                max-height: 100%;
            }}
            .chat-messages::-webkit-scrollbar {{
                width: 8px;
            }}
            .chat-messages::-webkit-scrollbar-track {{
                background: #f1f1f1;
            }}
            .chat-messages::-webkit-scrollbar-thumb {{
                background: #888;
                border-radius: 4px;
            }}
            .chat-messages::-webkit-scrollbar-thumb:hover {{
                background: #555;
            }}
            .message {{
                margin-bottom: 20px;
            }}
            .message-header {{
                display: flex;
                align-items: center;
                margin-bottom: 8px;
                gap: 10px;
            }}
            .message-label {{
                font-weight: 600;
                font-size: 14px;
                color: #333;
            }}
            .message-time {{
                font-size: 12px;
                color: #999;
            }}
            .collapse-btn {{
                margin-left: auto;
                padding: 4px 12px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
            }}
            .collapse-btn:hover {{
                background: #5568d3;
            }}
            .message-content {{
                padding: 15px;
                border-radius: 8px;
                background: white;
                border: 1px solid #e0e0e0;
                line-height: 1.6;
                word-wrap: break-word;
                overflow-wrap: break-word;
                max-width: 100%;
            }}
            .message-content.collapsed {{
                display: none;
            }}
            .message.user .message-content {{
                background: #667eea;
                color: white;
                border-color: #667eea;
                max-width: 70%;
            }}
            .message.agent .message-content {{
                background: white;
                max-width: 85%;
            }}
            .streaming-indicator {{
                display: inline-block;
                width: 8px;
                height: 8px;
                background: #4caf50;
                border-radius: 50%;
                animation: pulse 1.5s ease-in-out infinite;
                margin-left: 8px;
            }}
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.3; }}
            }}
            .chat-input-container {{
                padding: 20px;
                background: white;
                border-top: 1px solid #e0e0e0;
            }}
            .input-wrapper {{
                display: flex;
                gap: 10px;
                max-width: 1200px;
                margin: 0 auto;
            }}
            .chat-input {{
                flex: 1;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                font-size: 14px;
                font-family: inherit;
            }}
            .chat-input:focus {{
                outline: none;
                border-color: #667eea;
            }}
            .send-btn {{
                padding: 12px 30px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: background 0.2s;
            }}
            .send-btn:hover {{
                background: #5568d3;
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
            .no-agent {{
                text-align: center;
                padding: 100px 20px;
                color: #999;
                font-size: 18px;
            }}
            pre {{
                background: #f5f5f5;
                padding: 10px;
                border-radius: 4px;
                overflow-x: auto;
                font-size: 13px;
            }}
            .status-message {{
                color: #666;
                font-size: 13px;
                font-style: italic;
                padding: 8px;
                background: #f0f0f0;
                border-radius: 4px;
                margin: 8px 0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>🤖 Cortex Agent Chat (Streaming)</h1>
                <div class="user-info">Logged in as: {user.get('email', 'User')}</div>
            </div>
            <div>
                <a href="/logout" class="btn">Logout</a>
            </div>
        </div>
        
        <div class="main-container">
            <div class="sidebar">
                <div class="sidebar-header">
                    <h2>🤖 Cortex Agents</h2>
                    <label class="agent-selector-label">Select an agent:</label>
                    <select class="agent-select" id="agentSelect" onchange="selectAgentFromDropdown()">
                        <option value="">Loading agents...</option>
                    </select>
                    <button class="clear-btn" id="clearBtn" onclick="clearChat()" disabled>
                        🗑️ Clear Chat
                    </button>
                </div>
                <div class="sidebar-info" id="agentInfo">
                    <div class="info-card">
                        <h3>ℹ️ How to use</h3>
                        <p>1. Select an agent from the dropdown above</p>
                        <p>2. Type your question in the chat</p>
                        <p>3. Watch the response stream in real-time</p>
                        <p>4. Click "Collapse" to minimize messages</p>
                    </div>
                </div>
            </div>
            
            <div class="chat-area">
                <div class="chat-messages" id="chatMessages">
                    <div class="no-agent">
                        👈 Select an agent from the sidebar to start chatting
                    </div>
                </div>
                
                <div class="chat-input-container">
                    <div class="input-wrapper">
                        <input 
                            type="text" 
                            class="chat-input" 
                            id="messageInput" 
                            placeholder="Select an agent first..."
                            disabled
                            autocomplete="off"
                        />
                        <button class="send-btn" id="sendBtn" onclick="sendMessage()" disabled>
                            Send
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let selectedAgent = null;
            let messageCounter = 0;
            let allAgents = [];
            
            // Load agents on page load
            window.addEventListener('DOMContentLoaded', function() {{
                loadAgents();
            }});
            
            async function loadAgents() {{
                try {{
                    const response = await fetch('/api/agents', {{
                        credentials: 'same-origin'
                    }});
                    
                    if (!response.ok) {{
                        throw new Error(`HTTP ${{response.status}}`);
                    }}
                    
                    const agents = await response.json();
                    allAgents = agents;
                    
                    const agentSelect = document.getElementById('agentSelect');
                    agentSelect.innerHTML = '<option value="">-- Select an agent --</option>';
                    
                    if (agents.length === 0) {{
                        agentSelect.innerHTML = '<option value="">No agents found</option>';
                        return;
                    }}
                    
                    agents.forEach((agent, index) => {{
                        const option = document.createElement('option');
                        option.value = index;
                        option.textContent = agent.name;
                        option.title = agent.full_path;  // Show full path on hover
                        agentSelect.appendChild(option);
                    }});
                }} catch (error) {{
                    console.error('Failed to load agents:', error);
                    const agentSelect = document.getElementById('agentSelect');
                    agentSelect.innerHTML = `<option value="">Error: ${{error.message}}</option>`;
                    
                    // Show error in sidebar
                    const agentInfo = document.getElementById('agentInfo');
                    agentInfo.innerHTML = `
                        <div style="background: #fee; border: 1px solid #fcc; color: #c00; padding: 15px; border-radius: 5px; margin: 10px;">
                            <strong>⚠️ Failed to load agents</strong>
                            <p style="margin-top: 8px; font-size: 12px;">${{error.message}}</p>
                            <p style="margin-top: 8px; font-size: 11px;">Try refreshing the page or checking the browser console for details.</p>
                        </div>
                    `;
                }}
            }}
            
            function selectAgentFromDropdown() {{
                const agentSelect = document.getElementById('agentSelect');
                const selectedIndex = agentSelect.value;
                
                if (!selectedIndex || selectedIndex === '') {{
                    return;
                }}
                
                const agent = allAgents[parseInt(selectedIndex)];
                selectAgent(agent);
            }}
            
            function selectAgent(agent) {{
                selectedAgent = agent;
                
                // Enable input and clear button
                const input = document.getElementById('messageInput');
                const sendBtn = document.getElementById('sendBtn');
                const clearBtn = document.getElementById('clearBtn');
                input.disabled = false;
                sendBtn.disabled = false;
                clearBtn.disabled = false;
                input.placeholder = `Ask ${{agent.name}} a question...`;
                input.focus();
                
                // Update sidebar info
                const agentInfo = document.getElementById('agentInfo');
                agentInfo.innerHTML = `
                    <div class="info-card">
                        <h3>📍 Selected Agent</h3>
                        <p><span class="info-label">Name:</span> ${{agent.name}}</p>
                        <p><span class="info-label">Path:</span> ${{agent.full_path}}</p>
                    </div>
                    <div class="info-card">
                        <h3>ℹ️ How to use</h3>
                        <p>• Type your question below</p>
                        <p>• Responses stream in real-time</p>
                        <p>• Click "Collapse" to minimize messages</p>
                        <p>• Use "Clear Chat" to start over</p>
                    </div>
                `;
                
                // Clear messages and show welcome
                const messages = document.getElementById('chatMessages');
                messages.innerHTML = `
                    <div class="message agent">
                        <div class="message-header">
                            <span class="message-label">Agent: ${{agent.name}}</span>
                            <span class="message-time">${{new Date().toLocaleTimeString()}}</span>
                        </div>
                        <div class="message-content">
                            👋 Hello! I'm ${{agent.name}}. How can I help you today?
                        </div>
                    </div>
                `;
            }}
            
            function clearChat() {{
                if (!selectedAgent) return;
                
                if (confirm('Clear all messages in this chat?')) {{
                    const messages = document.getElementById('chatMessages');
                    messages.innerHTML = `
                        <div class="message agent">
                            <div class="message-header">
                                <span class="message-label">Agent: ${{selectedAgent.name}}</span>
                                <span class="message-time">${{new Date().toLocaleTimeString()}}</span>
                            </div>
                            <div class="message-content">
                                💬 Chat cleared. How can I help you?
                            </div>
                        </div>
                    `;
                    messageCounter = 0;
                    
                    // Focus back on input
                    document.getElementById('messageInput').focus();
                }}
            }}
            
            // Allow Enter to send
            document.getElementById('messageInput').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter' && !e.shiftKey && !this.disabled) {{
                    e.preventDefault();
                    sendMessage();
                }}
            }});
            
            function scrollToBottom() {{
                const messages = document.getElementById('chatMessages');
                setTimeout(() => {{
                    messages.scrollTop = messages.scrollHeight;
                }}, 100);
            }}
            
            function addUserMessage(text) {{
                const messagesDiv = document.getElementById('chatMessages');
                const messageId = 'msg-' + (messageCounter++);
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message user';
                messageDiv.id = messageId;
                messageDiv.innerHTML = `
                    <div class="message-header">
                        <span class="message-label">You</span>
                        <span class="message-time">${{new Date().toLocaleTimeString()}}</span>
                    </div>
                    <div class="message-content">${{escapeHtml(text)}}</div>
                `;
                messagesDiv.appendChild(messageDiv);
                scrollToBottom();
                return messageId;
            }}
            
            function addAgentMessage(isStreaming = false) {{
                const messagesDiv = document.getElementById('chatMessages');
                const messageId = 'msg-' + (messageCounter++);
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message agent';
                messageDiv.id = messageId;
                messageDiv.innerHTML = `
                    <div class="message-header">
                        <span class="message-label">
                            Agent: ${{selectedAgent.name}}
                            ${{isStreaming ? '<span class="streaming-indicator"></span>' : ''}}
                        </span>
                        <span class="message-time">${{new Date().toLocaleTimeString()}}</span>
                        <button class="collapse-btn" onclick="toggleCollapse('${{messageId}}')">Collapse</button>
                    </div>
                    <div class="thinking-section" id="thinking-${{messageId}}" style="display: none;">
                        <details style="margin-bottom: 10px; background: #f0f0f0; padding: 10px; border-radius: 5px; border-left: 3px solid #667eea;">
                            <summary style="cursor: pointer; font-weight: 600; color: #667eea; user-select: none;">🤔 Thinking process (click to expand)</summary>
                            <div class="thinking-content" style="margin-top: 10px; color: #555; font-size: 13px; line-height: 1.6;"></div>
                        </details>
                    </div>
                    <div class="status-section" id="status-${{messageId}}" style="display: none; margin-bottom: 10px;"></div>
                    <div class="message-content"></div>
                `;
                messagesDiv.appendChild(messageDiv);
                scrollToBottom();
                return messageId;
            }}
            
            function updateThinkingContent(messageId, thinkingText) {{
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const thinkingSection = document.getElementById(`thinking-${{messageId}}`);
                    const thinkingContent = thinkingSection.querySelector('.thinking-content');
                    
                    // Show the thinking section
                    thinkingSection.style.display = 'block';
                    
                    // Get current content
                    const currentText = thinkingContent.getAttribute('data-raw-text') || '';
                    const newText = currentText + thinkingText;
                    thinkingContent.setAttribute('data-raw-text', newText);
                    
                    // Format the text
                    const formattedHtml = formatThinkingContent(newText);
                    thinkingContent.innerHTML = formattedHtml;
                }}
            }}
            
            function updateThinkingHTML(messageId, html) {{
                // Add raw HTML to thinking section (for SQL blocks)
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const thinkingSection = document.getElementById(`thinking-${{messageId}}`);
                    const thinkingContent = thinkingSection.querySelector('.thinking-content');
                    
                    // Show the thinking section
                    thinkingSection.style.display = 'block';
                    
                    // Append HTML
                    thinkingContent.innerHTML += html;
                }}
            }}
            
            function formatThinkingContent(text) {{
                // Simple escape and line break conversion - no regex detection
                let formatted = escapeHtml(text);
                formatted = formatted.replace(/\\n/g, '<br>');
                return formatted;
            }}
            
            function updateStatusMessage(messageId, statusText) {{
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const statusSection = document.getElementById(`status-${{messageId}}`);
                    
                    // Show the status section
                    statusSection.style.display = 'block';
                    
                    // Replace with latest status (not append)
                    statusSection.innerHTML = `<div class="status-message">${{statusText}}</div>`;
                }}
            }}
            
            function clearStatusMessage(messageId) {{
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const statusSection = document.getElementById(`status-${{messageId}}`);
                    statusSection.style.display = 'none';
                    statusSection.innerHTML = '';
                }}
            }}
            
            function updateMessageContent(messageId, content) {{
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const contentDiv = messageDiv.querySelector('.message-content');
                    contentDiv.innerHTML = formatContent(content);
                    
                    // Check if user is near bottom before auto-scrolling
                    const messages = document.getElementById('chatMessages');
                    const isNearBottom = messages.scrollHeight - messages.scrollTop - messages.clientHeight < 100;
                    
                    // Only auto-scroll if user is near bottom (prevents jumping during manual scroll)
                    if (isNearBottom) {{
                        scrollToBottom();
                    }}
                }}
            }}
            
            function finalizeMessage(messageId) {{
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const indicator = messageDiv.querySelector('.streaming-indicator');
                    if (indicator) indicator.remove();
                    
                    // Clear status message when done
                    clearStatusMessage(messageId);
                }}
            }}
            
            function toggleCollapse(messageId) {{
                const messageDiv = document.getElementById(messageId);
                if (messageDiv) {{
                    const content = messageDiv.querySelector('.message-content');
                    const btn = messageDiv.querySelector('.collapse-btn');
                    content.classList.toggle('collapsed');
                    btn.textContent = content.classList.contains('collapsed') ? 'Expand' : 'Collapse';
                }}
            }}
            
            function formatContent(text) {{
                // If content already has HTML tags (tables, charts), don't escape
                if (text.includes('<table') || text.includes('<div id=')) {{
                    // Already formatted HTML - just process markdown in text portions
                    let formatted = text;
                    // Bold (only in text, not in HTML tags)
                    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
                    // Line breaks (but not in pre/code blocks)
                    formatted = formatted.replace(/\\n/g, '<br>');
                    return formatted;
                }}
                
                // Plain text - escape and format
                text = escapeHtml(text);
                // Bold
                text = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
                // Code blocks
                text = text.replace(/```([\\s\\S]*?)```/g, '<pre>$1</pre>');
                // Line breaks
                text = text.replace(/\\n/g, '<br>');
                return text;
            }}
            
            function escapeHtml(text) {{
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }}
            
            function formatTableData(data) {{
                // Handle different table data formats
                let rows = [];
                let columns = [];
                
                if (!data) {{
                    return '<p style="color: #999;">No table data</p>';
                }}
                
                // Format 1: data.rows array (object per row)
                if (data.rows && Array.isArray(data.rows) && data.rows.length > 0) {{
                    rows = data.rows;
                    columns = Object.keys(rows[0]);
                }}
                // Format 2: data.data array with metadata (result_set format)
                else if (data.data && Array.isArray(data.data)) {{
                    const dataArray = data.data;
                    
                    // Get column names from metadata if available
                    if (data.resultSetMetaData && Array.isArray(data.resultSetMetaData.rowType)) {{
                        columns = data.resultSetMetaData.rowType.map(col => col.name);
                    }} else if (data.rowType && Array.isArray(data.rowType)) {{
                        columns = data.rowType.map(col => col.name);
                    }} else if (dataArray.length > 0 && Array.isArray(dataArray[0])) {{
                        // Generate column names (Col1, Col2, ...)
                        columns = dataArray[0].map((_, idx) => `Col${{idx + 1}}`);
                    }}
                    
                    // Convert array of arrays to array of objects
                    rows = dataArray.map(rowArray => {{
                        const rowObj = {{}};
                        columns.forEach((col, idx) => {{
                            rowObj[col] = rowArray[idx];
                        }});
                        return rowObj;
                    }});
                }}
                // Format 3: plain array of objects
                else if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object') {{
                    rows = data;
                    columns = Object.keys(rows[0]);
                }}
                // Format 4: plain array of arrays
                else if (Array.isArray(data) && data.length > 0 && Array.isArray(data[0])) {{
                    columns = data[0].map((_, idx) => `Col${{idx + 1}}`);
                    rows = data.map(rowArray => {{
                        const rowObj = {{}};
                        columns.forEach((col, idx) => {{
                            rowObj[col] = rowArray[idx];
                        }});
                        return rowObj;
                    }});
                }}
                
                if (rows.length === 0) {{
                    return '<p style="color: #999;">Empty table (no rows)</p>';
                }}
                
                let html = '<div style="margin: 15px 0;"><strong>📊 Data Table:</strong></div>';
                html += '<table style="width: 100%; border-collapse: collapse; font-size: 13px; background: white; border: 1px solid #e0e0e0;">';
                html += '<thead><tr>';
                
                columns.forEach(col => {{
                    html += `<th style="padding: 10px; text-align: left; background: #667eea; color: white; font-weight: 600;">${{col}}</th>`;
                }});
                html += '</tr></thead><tbody>';
                
                rows.forEach((row, idx) => {{
                    html += `<tr style="border-bottom: 1px solid #e0e0e0; ${{idx % 2 === 0 ? 'background: #f9f9f9;' : ''}}">`;
                    columns.forEach(col => {{
                        const val = row[col];
                        html += `<td style="padding: 8px;">${{val !== null && val !== undefined ? escapeHtml(String(val)) : 'NULL'}}</td>`;
                    }});
                    html += '</tr>';
                }});
                
                html += '</tbody></table>';
                return html;
            }}
            
            function renderChart(containerId, chartSpec) {{
                if (typeof vegaEmbed === 'undefined') {{
                    const container = document.getElementById(containerId);
                    if (container) container.innerHTML = '<div style="color: #e74c3c;">Vega-Lite library not loaded</div>';
                    return;
                }}
                
                // Parse chart spec if string
                let spec = chartSpec;
                if (typeof chartSpec === 'string') {{
                    try {{
                        spec = JSON.parse(chartSpec);
                    }} catch (e) {{
                        console.error('Failed to parse chart spec:', e);
                        return;
                    }}
                }}
                
                // Apply white theme
                if (!spec.background) spec.background = '#ffffff';
                if (!spec.config) spec.config = {{}};
                if (!spec.config.axis) spec.config.axis = {{}};
                spec.config.axis.labelColor = spec.config.axis.labelColor || '#0f172a';
                spec.config.axis.titleColor = spec.config.axis.titleColor || '#0f172a';
                
                // Render chart
                const container = document.getElementById(containerId);
                if (container) {{
                    vegaEmbed(container, spec, {{
                        actions: {{ export: true, source: false, compiled: false, editor: false }},
                        theme: 'latimes'
                    }}).catch(err => {{
                        console.error('Chart error:', err);
                        container.innerHTML = `<div style="color: #e74c3c; padding: 20px;">Failed to render chart</div>`;
                    }});
                }}
            }}
            
            async function sendMessage() {{
                if (!selectedAgent) {{
                    alert('Please select an agent first');
                    return;
                }}
                
                const input = document.getElementById('messageInput');
                const sendBtn = document.getElementById('sendBtn');
                const message = input.value.trim();
                
                if (!message) return;
                
                // Disable input
                input.disabled = true;
                sendBtn.disabled = true;
                
                // Add user message
                addUserMessage(message);
                input.value = '';
                
                // Add agent message with streaming indicator
                const agentMessageId = addAgentMessage(true);
                let streamedContent = '';
                let pendingCharts = [];  // Store charts to render after streaming completes
                
                try {{
                    const response = await fetch('/api/cortex/agent/chat', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            agent_database: selectedAgent.database,
                            agent_schema: selectedAgent.schema,
                            agent_name: selectedAgent.name,
                            message: message
                        }})
                    }});
                    
                    if (!response.ok) {{
                        const errorData = await response.json();
                        throw new Error(errorData.detail || 'Failed to send message');
                    }}
                    
                    // Handle SSE streaming
                    const reader = response.body.getReader();
                    const decoder = new TextDecoder();
                    let buffer = '';
                    
                    while (true) {{
                        const {{done, value}} = await reader.read();
                        if (done) break;
                        
                        buffer += decoder.decode(value, {{stream: true}});
                        const lines = buffer.split('\\n');
                        buffer = lines.pop() || '';
                        
                        for (const line of lines) {{
                            if (line.trim() === '' || !line.startsWith('data: ')) continue;
                            
                            const data = line.substring(6).trim();
                            
                            if (data === '[DONE]') {{
                                finalizeMessage(agentMessageId);
                                break;
                            }}
                            
                                try {{
                                    const json = JSON.parse(data);
                                    
                                    if (json.type === 'thinking') {{
                                        // Regular thinking text
                                        updateThinkingContent(agentMessageId, json.content);
                                        
                                    }} else if (json.type === 'message') {{
                                        // Main response content - clear status when answer starts
                                        if (streamedContent === '') {{
                                            clearStatusMessage(agentMessageId);
                                        }}
                                        streamedContent += json.content;
                                        updateMessageContent(agentMessageId, streamedContent);
                                        
                                    }} else if (json.type === 'status') {{
                                        // Status updates - show temporarily (replaces previous status)
                                        updateStatusMessage(agentMessageId, json.content);
                                        
                                    }} else if (json.type === 'sql') {{
                                        // SQL query from Cortex Analyst - add to thinking section
                                        console.log('📊 SQL received from backend');
                                        
                                        let sqlHtml = '<div style="margin: 15px 0; background: #2d2d2d; border-radius: 5px; padding: 15px; overflow-x: auto; border-left: 3px solid #a6e22e;">';
                                        sqlHtml += '<div style="color: #a6e22e; font-weight: 600; margin-bottom: 10px; font-size: 13px;">📊 SQL Query (Cortex Analyst)</div>';
                                        if (json.explanation) {{
                                            sqlHtml += '<div style="color: #ccc; margin-bottom: 10px; font-size: 12px;">' + escapeHtml(json.explanation) + '</div>';
                                        }}
                                        sqlHtml += '<pre style="margin: 0; color: #f8f8f2; font-family: \\'Courier New\\', monospace; font-size: 12px; background: transparent; padding: 0; line-height: 1.6; white-space: pre-wrap;">' + escapeHtml(json.sql) + '</pre>';
                                        sqlHtml += '</div>';
                                        
                                        updateThinkingHTML(agentMessageId, sqlHtml);
                                        
                                    }} else if (json.type === 'table') {{
                                        // Table data - clear status and add to content
                                        clearStatusMessage(agentMessageId);
                                        try {{
                                            const tableHtml = formatTableData(json.data);
                                            streamedContent += tableHtml;
                                            updateMessageContent(agentMessageId, streamedContent);
                                        }} catch (tableError) {{
                                            console.error('Table formatting error:', tableError, json.data);
                                            streamedContent += '<p style="color: #e74c3c;">Error displaying table</p>';
                                            updateMessageContent(agentMessageId, streamedContent);
                                        }}
                                        
                                    }} else if (json.type === 'chart') {{
                                        // Chart - store for rendering after streaming completes
                                        clearStatusMessage(agentMessageId);
                                        
                                        const chartId = 'chart-' + agentMessageId + '-' + pendingCharts.length;
                                        const chartHtml = `
                                            <div style="margin: 20px 0;">
                                                <div style="font-weight: 600; margin-bottom: 10px; color: #667eea;">📈 Chart Visualization:</div>
                                                <div id="${{chartId}}" style="width: 100%; min-height: 400px; background: white; border-radius: 5px; padding: 15px; border: 1px solid #e0e0e0;"></div>
                                            </div>
                                        `;
                                        streamedContent += chartHtml;
                                        updateMessageContent(agentMessageId, streamedContent);
                                        
                                        // Store chart for rendering after streaming completes
                                        pendingCharts.push({{ id: chartId, spec: json.chart_spec }});
                                        
                                    }} else if (json.content) {{
                                        // Fallback for untyped content
                                        streamedContent += json.content;
                                        updateMessageContent(agentMessageId, streamedContent);
                                        
                                    }} else if (json.error) {{
                                        throw new Error(json.error);
                                    }}
                                }} catch (e) {{
                                    if (e instanceof SyntaxError) {{
                                        // JSON parse error - ignore
                                    }} else {{
                                        console.error('Message processing error:', e, data);
                                        throw e;
                                    }}
                                }}
                        }}
                    }}
                    
                    finalizeMessage(agentMessageId);
                    
                    // Render all pending charts now that streaming is complete
                    if (pendingCharts.length > 0) {{
                        setTimeout(() => {{
                            pendingCharts.forEach(chart => renderChart(chart.id, chart.spec));
                        }}, 200);
                    }}
                    
                }} catch (error) {{
                    updateMessageContent(agentMessageId, `<div class="error">Error: ${{error.message}}</div>`);
                    finalizeMessage(agentMessageId);
                }} finally {{
                    // Re-enable input
                    input.disabled = false;
                    sendBtn.disabled = false;
                    input.focus();
                }}
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# --- API ENDPOINTS ---

@app.get("/api/agents")
async def list_agents(
    user: dict = Depends(get_current_user),
    access_token: str = Depends(get_access_token)
):
    """List all available Cortex Agents in the account"""
    try:
        # Connect to Snowflake
        conn_params = {
            'account': SNOWFLAKE_ACCOUNT,
            'user': user.get('email', 'unknown'),
            'authenticator': 'oauth',
            'token': access_token,
            'warehouse': SNOWFLAKE_WAREHOUSE,
            'database': SNOWFLAKE_DATABASE,
            'schema': SNOWFLAKE_SCHEMA
        }
        
        conn = sc.connect(**conn_params)
        cs = conn.cursor()
        
        # Execute SHOW AGENTS query
        cs.execute("SHOW AGENTS IN ACCOUNT")
        agents_raw = cs.fetchall()
        
        # Get column names
        columns = [desc[0] for desc in cs.description]
        
        # Parse agents
        agents = []
        for row in agents_raw:
            agent_dict = dict(zip(columns, row))
            full_path = f"{agent_dict.get('database_name')}.{agent_dict.get('schema_name')}.{agent_dict.get('name')}"
            agents.append({
                "name": agent_dict.get('name'),
                "database": agent_dict.get('database_name'),
                "schema": agent_dict.get('schema_name'),
                "full_path": full_path,
                "created_on": str(agent_dict.get('created_on', '')),
                "owner": agent_dict.get('owner', '')
            })
        
        cs.close()
        conn.close()
        
        return JSONResponse(content=agents)
        
    except Exception as e:
        print(f"❌ Error listing agents: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list agents: {str(e)}")

@app.post("/api/cortex/agent/chat")
async def agent_chat_stream(
    request: Request,
    user: dict = Depends(get_current_user),
    access_token: str = Depends(get_access_token)
):
    """Stream chat response from Cortex Agent using SSE"""
    try:
        body = await request.json()
        agent_database = body.get("agent_database")
        agent_schema = body.get("agent_schema")
        agent_name = body.get("agent_name")
        message = body.get("message")
        
        if not all([agent_database, agent_schema, agent_name, message]):
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        print(f"🤖 Agent Chat - {agent_database}.{agent_schema}.{agent_name}")
        
        # Establish Snowflake connection to get REST token
        # Don't close it yet - we'll keep it alive for the stream
        conn_params = {
            'account': SNOWFLAKE_ACCOUNT,
            'user': user.get('email', 'unknown'),
            'authenticator': 'oauth',
            'token': access_token,
            'warehouse': SNOWFLAKE_WAREHOUSE,
            'database': SNOWFLAKE_DATABASE,
            'schema': SNOWFLAKE_SCHEMA
        }
        
        try:
            conn = sc.connect(**conn_params)
        except Exception as e:
            raise HTTPException(
                status_code=401,
                detail=f"Could not connect to Snowflake. Your session may have expired. Please logout and login again."
            )
        
        # Get the REST token and build API URL
        rest_token = conn.rest.token
        host = conn.host.replace('_', '-')
        agent_name_encoded = quote(agent_name)
        agent_url = f"https://{host}/api/v2/databases/{agent_database}/schemas/{agent_schema}/agents/{agent_name_encoded}:run"
        
        # Prepare request - use the REST token from the active connection
        # For streaming responses
        headers = {
            "Authorization": f'Snowflake Token="{rest_token}"',
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "User-Agent": "FastAPI-Cortex-Agent-Client/1.0"
        }
        
        # Cortex Agent API format - proper nested content structure with streaming
        request_body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": message
                        }
                    ]
                }
            ],
            "tool_choice": {"type": "auto"},
            "stream": True
        }
        
        # Stream the response using SSE
        async def event_stream():
            try:
                response = requests.post(
                    agent_url,
                    headers=headers,
                    json=request_body,
                    stream=True,
                    timeout=60
                )
                
                if response.status_code != 200:
                    error_msg = response.text or f"HTTP {response.status_code}"
                    try:
                        error_json = json.loads(error_msg)
                        error_detail = error_json.get('message', error_msg)
                    except:
                        error_detail = error_msg
                    
                    error_obj = {"error": str(error_detail)}
                    yield f"data: {json.dumps(error_obj)}\n\n"
                    yield "data: [DONE]\n\n"
                    conn.close()
                    return
                
                # Handle SSE streaming response
                # Based on: https://github.com/sfc-gh-mwalli/CortexAgentStreamlit
                buffer_lines = []
                chunk_count = 0
                has_sent_text = False  # Track if we've sent text content
                
                for line in response.iter_lines(decode_unicode=True):
                    if line is None:
                        continue
                    
                    chunk_count += 1
                    line = line.strip('\n')
                    
                    # Empty line signals end of an SSE event block
                    if not line:
                        if buffer_lines:
                            # Parse the complete SSE block
                            event_data = parse_sse_block(buffer_lines)
                            buffer_lines = []
                            
                            if event_data:
                                event_type = event_data.get('event')
                                
                                # Handle different event types based on:
                                # https://github.com/sfc-gh-mwalli/CortexAgentStreamlit
                                
                                if event_type == 'response.thinking.delta':
                                    # Thinking process - collapsible section
                                    thinking_text = event_data.get('text', '')
                                    if thinking_text:
                                        yield f"data: {json.dumps({'content': thinking_text, 'type': 'thinking'})}\n\n"
                                        await asyncio.sleep(0)
                                
                                elif event_type == 'response.text.delta':
                                    # Final answer streaming
                                    text = event_data.get('text', '')
                                    if text:
                                        has_sent_text = True
                                        yield f"data: {json.dumps({'content': text, 'type': 'message'})}\n\n"
                                        await asyncio.sleep(0)
                                
                                elif event_type == 'response.table':
                                    # Table data from agent
                                    table_content = event_data.get('table') or event_data.get('json') or event_data.get('content')
                                    
                                    if table_content:
                                        yield f"data: {json.dumps({'type': 'table', 'data': table_content})}\n\n"
                                        await asyncio.sleep(0)
                                
                                elif event_type == 'response.chart':
                                    # Chart from agent
                                    chart_spec = None
                                    
                                    # Try different chart spec locations
                                    if isinstance(event_data.get('chart_spec'), str):
                                        chart_spec = event_data['chart_spec']
                                    elif isinstance(event_data.get('chart'), dict):
                                        if isinstance(event_data['chart'].get('chart_spec'), str):
                                            chart_spec = event_data['chart']['chart_spec']
                                        elif event_data['chart'].get('mark') or event_data['chart'].get('encoding'):
                                            chart_spec = json.dumps(event_data['chart'])
                                    elif isinstance(event_data.get('json'), dict):
                                        j = event_data['json']
                                        if j.get('mark') or j.get('encoding'):
                                            chart_spec = json.dumps(j)
                                    
                                    if chart_spec:
                                        yield f"data: {json.dumps({'type': 'chart', 'chart_spec': chart_spec})}\n\n"
                                        await asyncio.sleep(0)
                                
                                elif event_type == 'response.tool_use':
                                    # Tool usage notification
                                    tool_type = event_data.get('tool_type', '')
                                    tool_name = event_data.get('tool_name', '')
                                    tool_msg = f"🔧 Using tool: {tool_name or tool_type}".strip()
                                    yield f"data: {json.dumps({'content': tool_msg, 'type': 'status'})}\n\n"
                                    await asyncio.sleep(0)
                                
                                elif event_type == 'response.tool_result.analyst.delta':
                                    # Cortex Analyst tool result with SQL and data
                                    # Ref: https://docs.snowflake.com/en/user-guide/snowflake-cortex/cortex-agents-run#label-snowflake-agent-run-cortexanalysttoolresultdelta
                                    delta = event_data.get('delta', {})
                                    
                                    if not isinstance(delta, dict):
                                        continue
                                    
                                    # Extract SQL and explanation from delta
                                    sql_query = delta.get('sql')
                                    sql_explanation = delta.get('sql_explanation')
                                    
                                    if sql_query:
                                        print(f"📊 SQL from analyst: {sql_query[:80]}...")
                                        
                                        # Send as a special SQL content type (not thinking text)
                                        yield f"data: {json.dumps({'type': 'sql', 'sql': sql_query, 'explanation': sql_explanation})}\n\n"
                                        await asyncio.sleep(0)
                                
                                elif event_type == 'response.status':
                                    # Status updates
                                    status_msg = event_data.get('message', '')
                                    if status_msg:
                                        yield f"data: {json.dumps({'content': f'⏳ {status_msg}', 'type': 'status'})}\n\n"
                                        await asyncio.sleep(0)
                                
                                elif event_type == 'error':
                                    # Error handling
                                    error_msg = event_data.get('message', 'Unknown error')
                                    print(f"❌ Agent error: {error_msg}")
                                    yield f"data: {json.dumps({'content': f'⚠️ Error: {error_msg}', 'type': 'message'})}\n\n"
                                    await asyncio.sleep(0)
                    else:
                        buffer_lines.append(line)
                
                # Send final done signal
                yield "data: [DONE]\n\n"
                print(f"✅ Stream complete")
                
            except Exception as e:
                print(f"❌ Streaming error: {str(e)}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                yield "data: [DONE]\n\n"
            finally:
                try:
                    conn.close()
                except:
                    pass
        
        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Agent chat error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "message": "Cortex Agent App running",
        "app": "agent_app",
        "port": APP_PORT
    }

if __name__ == "__main__":
    import uvicorn
    print("🤖 Starting Cortex Agent Application (Streaming)...")
    print(f"📍 Navigate to: http://localhost:{APP_PORT}")
    print(f"🔑 Client ID: {CLIENT_ID}")
    print(f"🔐 Auth Server: {OKTA_ISSUER}")
    print("🌊 Server-Sent Events (SSE) streaming enabled")
    print("🚀 Select an agent and start chatting!")
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)

