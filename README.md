# OAuth Authorization Code Flow with Snowflake Cortex Agents

A reference implementation of OAuth 2.0 Authorization Code Flow with PKCE for Snowflake applications. This repository demonstrates how to implement user-based authentication instead of service accounts, enabling individual user tracking and audit trails.

## Demo

![Cortex Agent Chat with OAuth](ext-oauth-sf-cortex-agents.gif)

*Real-time streaming chat with Snowflake Cortex Agents using OAuth authentication - each query runs as the authenticated user with full audit trail.*

## Why User-Based Authentication

Traditional Snowflake integrations typically use a shared service account, which creates several problems:

**Service Account Limitations:**
- No attribution for individual user actions
- Difficult to audit who accessed what data
- Single point of compromise affects all users
- Cannot enforce user-specific permissions
- Poor governance and compliance posture

**OAuth Benefits:**
- Every query runs as the authenticated user in Snowflake
- Complete audit trail with user attribution
- Compromised tokens isolated to individual users
- Native Snowflake RBAC applies per user
- Meets regulatory requirements (SOC 2, GDPR, HIPAA)
- No shared credentials to manage

### Query Attribution Example

**Before OAuth (Service Account):**
```
Query History:
- User: SERVICE_ACCOUNT
- Query: SELECT * FROM SENSITIVE_DATA
- Who ran this? Unknown
```

**After OAuth (Individual Identity):**
```
Query History:
- User: john.doe@company.com
- Query: SELECT * FROM SENSITIVE_DATA
- Timestamp: 2024-01-15 10:23:45
- IP Address: 192.168.1.100
```

## Project Structure

This repository contains three applications demonstrating OAuth implementations of increasing complexity:

### `oauth_testing/` - OAuth Fundamentals

Learn and test the OAuth flow step-by-step without application complexity.

**Contents:**
- `1-get_okta_token.py` - Interactive script to obtain refresh tokens
- `2-oauth_okta_snowflake.py` - Exchange refresh tokens for access tokens
- `3-validate-snowflake.py` - Test Snowflake connection with OAuth token

**Use Cases:**
- Testing OAuth configuration
- Understanding token lifecycle
- Debugging authentication issues

### `simple_app/` - Customer Application with Cortex Analyst

Production-ready FastAPI application demonstrating OAuth with Snowflake's Cortex Analyst for natural language queries.

**Contents:**
- Complete OAuth login/logout flow
- Cortex Analyst chatbot interface
- Natural language to SQL conversion
- Session management
- User dashboard

**Use Cases:**
- Customer-facing analytics portals
- Self-service data exploration
- Business intelligence dashboards
- AI-powered reporting

**Features:**
- Natural language queries ("Show me top 10 customers")
- Automatic SQL generation and execution
- Data visualization
- Row-level security per user

### `agent_app/` - Multi-Agent Streaming Chat

Advanced application with real-time streaming responses from multiple Cortex Agents.

**Contents:**
- Server-Sent Events (SSE) for real-time streaming
- Multi-agent selection interface
- Collapsible thinking process view
- Dynamic table and chart rendering
- Real-time status updates

**Use Cases:**
- AI assistant applications
- Multi-model AI workflows
- Real-time data analysis
- Decision support systems

**Features:**
- Real-time streaming responses
- Multiple specialized agents
- Agent reasoning visibility
- Interactive visualizations
- Contextual conversations

## OAuth Authorization Code Flow

### Overview

OAuth 2.0 is an industry-standard authorization protocol. Unlike shared service accounts, OAuth provides each user with individual, temporary credentials.

### Flow Steps

**Step 1: User Initiates Login**
- User clicks "Login"
- Application redirects to OAuth provider (Okta)
- User enters credentials
- Credentials never touch the application

**Step 2: Authorization Grant**
- OAuth provider validates user
- Generates single-use authorization code
- Redirects back to application with code
- Code expires in seconds

**Step 3: Token Exchange**
- Application exchanges authorization code for tokens
- Receives access token and refresh token
- Tokens are short-lived and revocable

**Step 4: Access Resources**
- Application presents access token to Snowflake
- Snowflake validates token and extracts user identity
- Query executes as the authenticated user

**Step 5: Token Refresh**
- Access token expires (typically 1 hour)
- Application uses refresh token to obtain new access token
- No user interaction required

### PKCE (Proof Key for Code Exchange)

PKCE adds additional security to the authorization code flow:

1. Application generates random `code_verifier` and derives `code_challenge`
2. Sends `code_challenge` with authorization request
3. Sends `code_verifier` with token exchange
4. Server validates they match

This prevents authorization code interception attacks, particularly important for mobile and single-page applications.

## Snowflake Configuration

### Security Integration

A Security Integration in Snowflake is required to validate OAuth tokens from external providers. This one-time configuration:

- Validates OAuth tokens from your authorization server
- Maps external user identities to Snowflake users
- Defines role access for authenticated users
- Establishes trust between Snowflake and your OAuth provider

#### Prerequisites for Security Integration

1. **ACCOUNTADMIN role** or a role with `CREATE INTEGRATION` privilege
2. OAuth provider configured (Okta, Azure AD, etc.)
3. Authorization server issuer URL
4. JWS keys endpoint URL

#### Step-by-Step: Create Security Integration

**1. Gather Required Information from Okta:**

From your Okta Authorization Server, you'll need:
- `OKTA_ISSUER` - The issuer URL (e.g., `https://your-domain.okta.com/oauth2/aus...`)
- `OKTA_JWS_KEY_ENDPOINT` - The JWKS URI (e.g., `https://your-domain.okta.com/oauth2/.../v1/keys`)
- Audience value - Your Snowflake account URL

**2. Execute the CREATE SECURITY INTEGRATION command in Snowflake:**

```sql
-- Create External OAuth Security Integration for Okta
CREATE OR REPLACE SECURITY INTEGRATION external_oauth_okta_cortex
    TYPE = EXTERNAL_OAUTH
    ENABLED = TRUE
    EXTERNAL_OAUTH_TYPE = OKTA
    EXTERNAL_OAUTH_ISSUER = 'https://your-domain.okta.com/oauth2/ausXXXXXXXXXXXXXXXX'
    EXTERNAL_OAUTH_JWS_KEYS_URL = 'https://your-domain.okta.com/oauth2/ausXXXXXXXXXXXXXXXX/v1/keys'
    EXTERNAL_OAUTH_AUDIENCE_LIST = ('https://your-account.snowflakecomputing.com')
    EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'sub'
    EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'EMAIL_ADDRESS'
    EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'
;

-- Grant USE_ANY_ROLE privilege to allow role switching
-- Option 1: Grant to PUBLIC (all users can switch roles)
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO PUBLIC;

-- Option 2: Grant to specific roles (more controlled)
-- GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO ROLE analyst;
-- GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO ROLE developer;
```

> **Important Notes:**
> - Replace `your-domain.okta.com` with your Okta domain
> - Replace `ausXXXXXXXXXXXXXXXX` with your authorization server ID
> - Replace `your-account.snowflakecomputing.com` with your Snowflake account URL
> - The `GRANT USE_ANY_ROLE` command is **required** when using `EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'`
> - Without this grant, users won't be able to switch roles even with `session:role-any` scope

**3. Key Parameters Explained:**

| Parameter | Description | Example Value |
|-----------|-------------|---------------|
| `EXTERNAL_OAUTH_ISSUER` | Your OAuth authorization server URL | `https://dev-123.okta.com/oauth2/aus...` |
| `EXTERNAL_OAUTH_JWS_KEYS_URL` | Endpoint for token validation keys | `https://dev-123.okta.com/.../v1/keys` |
| `EXTERNAL_OAUTH_AUDIENCE_LIST` | Your Snowflake account URL(s) | `('https://abc123.snowflakecomputing.com')` |
| `EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM` | Token claim to identify user | `sub` (subject) or `email` |
| `EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE` | Snowflake user attribute to match | `LOGIN_NAME` or `EMAIL_ADDRESS` |
| `EXTERNAL_OAUTH_ANY_ROLE_MODE` | Allow role switching | `ENABLE`, `DISABLE`, or `ENABLE_FOR_PRIVILEGE` |

**4. Understanding User Mapping:**

The security integration maps OAuth users to Snowflake users:

```sql
-- If using LOGIN_NAME mapping
-- Token claim 'sub' = 'john.doe@company.com'
-- Must match Snowflake user's LOGIN_NAME

-- Create Snowflake user matching OAuth identity
CREATE USER john_doe
    LOGIN_NAME = 'john.doe@company.com'
    EMAIL = 'john.doe@company.com'
    DEFAULT_ROLE = ANALYST
    MUST_CHANGE_PASSWORD = FALSE;
```

**5. Configuring Role Access:**

There are two approaches for role access:

**Option A: Any Role (Used in this repository)**
```sql
-- Security integration with ANY role enabled
EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'

-- CRITICAL: You must grant the USE_ANY_ROLE privilege!
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO PUBLIC;

-- In Okta, set scope to: session:role-any
-- Users can switch to any role they're granted in Snowflake
```

> **⚠️ Common Mistake:** Setting `EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'` without granting `USE_ANY_ROLE` privilege will cause authentication failures. Both are required!

**Option B: Specific Roles**
```sql
-- Security integration with specific roles
EXTERNAL_OAUTH_ANY_ROLE_MODE = 'DISABLE'

-- In Okta, create scopes for each role:
-- - session:role:analyst
-- - session:role:developer
-- - session:role:admin

-- Users can only use roles explicitly in their token scope
```

**6. Verify the Security Integration:**

```sql
-- Show all security integrations
SHOW INTEGRATIONS;

-- Describe your specific integration
DESC SECURITY INTEGRATION external_oauth_okta_cortex;

-- Check if USE_ANY_ROLE is granted
SHOW GRANTS ON INTEGRATION external_oauth_okta_cortex;

-- Expected output should show:
-- privilege    | granted_on   | name                          | granted_to
-- USE_ANY_ROLE | INTEGRATION  | external_oauth_okta_cortex    | PUBLIC

-- Test with a sample query (after connecting with OAuth)
SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT();
```

#### Common Configuration Scenarios

**For Development/Testing:**
```sql
CREATE OR REPLACE SECURITY INTEGRATION external_oauth_okta_dev
    TYPE = EXTERNAL_OAUTH
    ENABLED = TRUE
    EXTERNAL_OAUTH_TYPE = OKTA
    EXTERNAL_OAUTH_ISSUER = 'https://your-domain.okta.com/oauth2/ausXXXXXXXXXXXXXXXX'
    EXTERNAL_OAUTH_JWS_KEYS_URL = 'https://your-domain.okta.com/oauth2/ausXXXXXXXXXXXXXXXX/v1/keys'
    EXTERNAL_OAUTH_AUDIENCE_LIST = ('https://your-account.snowflakecomputing.com')
    EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'sub'
    EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'EMAIL_ADDRESS'
    EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE'  -- Flexible for development
;

-- Grant to all users for easy testing
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_dev TO PUBLIC;
```

**For Production:**
```sql
CREATE OR REPLACE SECURITY INTEGRATION external_oauth_okta_prod
    TYPE = EXTERNAL_OAUTH
    ENABLED = TRUE
    EXTERNAL_OAUTH_TYPE = OKTA
    EXTERNAL_OAUTH_ISSUER = 'https://your-domain.okta.com/oauth2/ausXXXXXXXXXXXXXXXX'
    EXTERNAL_OAUTH_JWS_KEYS_URL = 'https://your-domain.okta.com/oauth2/ausXXXXXXXXXXXXXXXX/v1/keys'
    EXTERNAL_OAUTH_AUDIENCE_LIST = ('https://your-account.snowflakecomputing.com')
    EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'sub'
    EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'EMAIL_ADDRESS'
    EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE_FOR_PRIVILEGE'  -- Controlled access
;

-- Grant to specific roles for controlled access
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_prod TO ROLE analyst;
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_prod TO ROLE developer;
```

#### Modifying Security Integration

You can update the security integration at any time:

```sql
-- Enable/disable the integration
ALTER SECURITY INTEGRATION external_oauth_okta_cortex SET ENABLED = FALSE;

-- Update the issuer URL
ALTER SECURITY INTEGRATION external_oauth_okta_cortex 
    SET EXTERNAL_OAUTH_ISSUER = 'https://new-domain.okta.com/oauth2/ausXXX';

-- Change role mode
ALTER SECURITY INTEGRATION external_oauth_okta_cortex 
    SET EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE';

-- Don't forget to grant USE_ANY_ROLE after enabling ANY role mode!
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO PUBLIC;

-- Revoke USE_ANY_ROLE if needed
REVOKE USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex FROM PUBLIC;
```

#### Troubleshooting Security Integration

**Issue: "Invalid OAuth access token"**
```sql
-- Check if integration is enabled
DESC SECURITY INTEGRATION external_oauth_okta_cortex;

-- Verify the issuer URL matches exactly (case-sensitive)
SHOW INTEGRATIONS LIKE 'external_oauth_okta_cortex';

-- Check integration settings
SELECT "name", "type", "enabled", "comment"
FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

-- Ensure JWS keys URL is accessible from Snowflake
-- Test the metadata endpoint in your browser:
-- https://your-domain.okta.com/oauth2/ausXXX/.well-known/oauth-authorization-server
```

**Issue: "User not found"**
```sql
-- Check user mapping
SELECT LOGIN_NAME, EMAIL 
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS 
WHERE LOGIN_NAME = 'user@company.com';

-- Create user if missing
CREATE USER IF NOT EXISTS user_name
    LOGIN_NAME = 'user@company.com'
    EMAIL = 'user@company.com';
```

**Issue: "Insufficient privileges to use role"**
```sql
-- If using ANY role mode, you MUST grant USE_ANY_ROLE privilege
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO PUBLIC;

-- Or grant role directly to user
GRANT ROLE analyst TO USER user_name;

-- Or grant to specific roles for more control
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO ROLE analyst;
```

**Issue: "Role specified in connect string does not exist or not authorized"**
```sql
-- This happens when ANY role mode is enabled but USE_ANY_ROLE isn't granted
-- Solution: Grant the privilege
GRANT USE_ANY_ROLE ON INTEGRATION external_oauth_okta_cortex TO PUBLIC;

-- Or verify user has the specific role
SHOW GRANTS TO USER user_name;
GRANT ROLE desired_role TO USER user_name;
```

#### Complete Setup Checklist

- [ ] Create OAuth application in Okta/Azure AD
- [ ] Configure authorization server with required scopes (include `session:role-any`)
- [ ] Note down issuer URL and JWS keys endpoint
- [ ] Create security integration in Snowflake (as ACCOUNTADMIN)
- [ ] **Grant USE_ANY_ROLE privilege** (if using ANY role mode)
- [ ] Create Snowflake users matching OAuth identities
- [ ] Grant appropriate roles to users
- [ ] Test connection with OAuth token
- [ ] Verify query attribution in query history

**Documentation:** [Configure Okta for External OAuth](https://docs.snowflake.com/en/user-guide/oauth-okta#create-a-security-integration-for-okta)

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Okta account with OAuth application
- Snowflake account with Security Integration configured
- Cortex Agents or Analyst (for AI applications)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd ext-oauth-snowflake-cortex-agents
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables for each app:**
   ```bash
   # For oauth_testing
   cd oauth_testing
   cp env.template .env
   # Edit .env with your credentials
   
   # For simple_app
   cd ../simple_app
   cp env.template .env
   # Edit .env with your credentials
   
   # For agent_app
   cd ../agent_app
   cp env.template .env
   # Edit .env with your credentials
   ```

4. **Run an application:**
   ```bash
   # Start the simple app
   cd simple_app
   python app.py
   
   # Or start the agent app
   cd agent_app
   python agent_app.py
   ```

## User Tracking in Snowflake

### Query Attribution

When using OAuth, every query in Snowflake shows the actual user:

```sql
-- View query history with real user identities
SELECT 
    query_text,
    user_name,  -- Shows: john.doe@company.com (not SERVICE_ACCOUNT)
    execution_time,
    warehouse_name,
    rows_produced
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE user_name = 'john.doe@company.com'
ORDER BY start_time DESC;
```

### Access Control

Leverage Snowflake's role-based access control per user:

```sql
-- Different users see different data based on their roles
-- John (Finance) sees financial data
-- Sarah (HR) sees employee data
-- Both use the same application!
```

### Compliance & Audit

Meet regulatory requirements with complete audit trails:

- **SOC 2:** Track all data access by individual
- **GDPR:** Identify who accessed personal data
- **HIPAA:** Audit access to protected health information
- **SOX:** Financial data access attribution

## Security Advantages

### 1. **No Shared Credentials**
- Each user has their own authentication
- Compromised token only affects one user
- Easy to revoke access for individual users

### 2. **Token-Based Security**
- Access tokens expire (typically 1 hour)
- Refresh tokens can be revoked remotely
- No passwords stored in application

### 3. **Principle of Least Privilege**
- Users only access what their Snowflake role permits
- Application can't bypass user permissions
- Fine-grained control per individual

### 4. **Audit & Compliance**
- Every action tied to real user identity
- Complete audit trail in Snowflake
- Meet regulatory requirements

### 5. **Enterprise SSO Integration**
- Leverage existing identity provider (Okta, Azure AD, etc.)
- Centralized user management
- MFA enforcement at identity provider level

## Use Cases

### Customer Analytics Portal
**Scenario:** Give customers access to their own analytics
- Each customer logs in with their credentials
- Sees only their own data (enforced by Snowflake roles)
- Full audit trail of what customers accessed

### Internal BI Dashboard
**Scenario:** Employees access business intelligence
- Finance team sees financial reports
- Sales team sees sales dashboards
- HR team sees workforce analytics
- All through the same application, secured by user roles

### AI-Powered Data Assistant
**Scenario:** Natural language queries for non-technical users
- Users ask questions in plain English
- Cortex Analyst generates SQL
- Results filtered by user's permissions
- Track which users are using AI features

### Partner Portal
**Scenario:** External partners access shared data
- Partners authenticate with their company credentials
- Access limited to agreed-upon data sets
- Full visibility into partner data usage

## Key Concepts

### OAuth Terminology

| Term | Definition | Example |
|------|------------|---------|
| **Authorization Server** | Issues tokens after authentication | Okta, Azure AD |
| **Client ID** | Unique identifier for your application | `0oayeyt1edk5NGAnT697` |
| **Client Secret** | Password for your application | Keep secure! |
| **Redirect URI** | Where user returns after login | `http://localhost:8001/callback` |
| **Scope** | Permissions requested | `openid profile email session:role-any` |
| **Access Token** | Short-lived token for API access | Expires in 1 hour |
| **Refresh Token** | Long-lived token to get new access tokens | Can be revoked |

### Snowflake Integration

**External OAuth Configuration:**

Snowflake requires a Security Integration to validate OAuth tokens. This configuration:
1. Establishes trust with the Okta authorization server
2. Maps the token's `sub` claim to Snowflake user identity
3. Executes queries as the authenticated user

```sql
-- Example Security Integration
CREATE SECURITY INTEGRATION okta_oauth
    TYPE = EXTERNAL_OAUTH
    ENABLED = TRUE
    EXTERNAL_OAUTH_TYPE = OKTA
    EXTERNAL_OAUTH_ISSUER = 'https://your-domain.okta.com/oauth2/...'
    EXTERNAL_OAUTH_JWS_KEYS_URL = 'https://your-domain.okta.com/.../v1/keys'
    EXTERNAL_OAUTH_AUDIENCE_LIST = ('https://your-account.snowflakecomputing.com')
    EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'sub'
    EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'LOGIN_NAME'
    EXTERNAL_OAUTH_ANY_ROLE_MODE = 'ENABLE';
```

See the [Snowflake Configuration](#snowflake-configuration) section for complete setup instructions.

## Technical Stack

- **Backend:** FastAPI (Python)
- **Authentication:** OAuth 2.0 Authorization Code Flow with PKCE
- **Identity Provider:** Okta (works with any OAuth provider)
- **Database:** Snowflake
- **AI/ML:** Snowflake Cortex (Agents & Analyst)
- **Frontend:** Vanilla JavaScript with SSE for streaming
- **Security:** Environment variables, httpOnly cookies, CSRF protection

## Additional Resources

### Documentation
- [Snowflake External OAuth](https://docs.snowflake.com/en/user-guide/oauth-external)
- [Okta OAuth 2.0](https://developer.okta.com/docs/concepts/oauth-openid/)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

## Contributing

This repository serves as a reference implementation. Feel free to:
- Adapt for your use case
- Extend with additional features
- Integrate with different identity providers
- Add more Cortex capabilities

## Security Best Practices

1. **Never commit `.env` files** - Contains sensitive credentials
2. **Rotate credentials regularly** - Update client secrets periodically
3. **Use HTTPS in production** - Never send tokens over HTTP
4. **Implement rate limiting** - Protect against token abuse
5. **Monitor token usage** - Track suspicious activity
6. **Validate tokens server-side** - Never trust client validation
7. **Use short token lifetimes** - Minimize exposure window
8. **Implement proper session management** - Secure cookies, session timeout

## License

This is a reference implementation for educational and demonstration purposes.

## FAQ

**Q: Why OAuth instead of username/password?**
A: OAuth is more secure (no password exposure), supports SSO, enables fine-grained permissions, and provides better audit trails.

**Q: Can I use Azure AD instead of Okta?**
A: Yes! The OAuth flow is the same. Just update your authorization server endpoints and configuration.

**Q: Do I need separate credentials for each app?**
A: No. Multiple applications can share the same authorization server. Each app gets its own Client ID for tracking.

**Q: How do I handle token expiration?**
A: Use refresh tokens to get new access tokens automatically. All three apps demonstrate this.

**Q: Is this production-ready?**
A: The authentication flow is production-grade. For production deployment, add proper error handling, monitoring, logging, and persistent session storage (Redis or database).

**Q: How much does this cost?**
A: OAuth integration is included with Snowflake Enterprise Edition and above. Okta has free developer accounts.

## Getting Started

To implement OAuth for your Snowflake applications:

1. Review `oauth_testing/` to understand the OAuth flow
2. Configure the Snowflake Security Integration
3. Run `simple_app/` to see a complete web application
4. Explore `agent_app/` for streaming and multi-agent features
5. Adapt the code for your specific requirements

This approach provides individual user attribution for every query, eliminating shared service accounts and improving security, compliance, and governance.

