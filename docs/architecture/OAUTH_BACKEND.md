# OAuth Architecture for Web and CLI Clients

## Overview

This document describes the architectural requirements and design patterns for supporting OAuth authentication across both web frontend and CLI applications. The current architecture supports only web-based OAuth flows, requiring CLI users to perform manual copy-paste authentication. This document proposes architectural solutions to enable seamless OAuth for both client types.

## Current Architecture

### Web-Only OAuth Design

**Components:**
- **Web Frontend**: React/Vue application at `https://any-llm.ai`
- **OAuth Backend**: FastAPI endpoints at `https://platform-api.any-llm.ai/api/v1/oauth`
- **OAuth Providers**: Google OAuth 2.0, GitHub OAuth 2.0
- **Session Store**: Cookie-based session management

**Authentication Flow:**
```
[Browser] → [Backend: /oauth/google/authorize]
          ↓ (redirect to Google)
[Google OAuth] → [User Login]
               ↓ (redirect to callback)
[Backend: /oauth/google/callback] → [Session Cookie]
                                   ↓
[Web Frontend] (authenticated)
```

**Current State Storage:**
- State parameters stored in server-side sessions
- Session identified by HTTP-only cookies
- Redirect URI hardcoded: `https://any-llm.ai/auth/google/callback`

### Architectural Constraints

**Why Current Architecture Fails for CLI:**

1. **Session Dependency**: State validation requires browser cookies, unavailable in CLI
2. **Fixed Redirect URI**: Single hardcoded redirect to web domain prevents localhost callbacks
3. **Stateful Design**: Server-side sessions create coupling between authorization and callback requests
4. **Browser Context**: OAuth flow assumes persistent browser session for state propagation

**Result**: CLI users must manually:
1. Open browser to authorization URL
2. Authenticate with provider
3. Intercept callback URL before page loads
4. Copy authorization code from URL
5. Paste code into CLI

## Proposed Architecture

### Design Principles

1. **Client Agnostic**: Backend should support both web and CLI without distinguishing clients
2. **Stateless State Management**: Remove session dependency for OAuth state validation
3. **Dynamic Redirect URIs**: Support both web callbacks and localhost callbacks
4. **Backward Compatible**: Existing web frontend continues working without changes
5. **Security-First**: Maintain or improve security properties of OAuth flow

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     OAuth Backend                               │
│                                                                 │
│  ┌──────────────┐           ┌──────────────┐                  │
│  │  Authorize   │           │  Callback    │                  │
│  │  Endpoint    │           │  Endpoint    │                  │
│  │              │           │              │                  │
│  │  - Validate  │           │  - Validate  │                  │
│  │    redirect  │           │    state     │                  │
│  │  - Generate  │           │  - Exchange  │                  │
│  │    state     │           │    code      │                  │
│  │  - Store in  │           │  - Issue JWT │                  │
│  │    Redis     │           │              │                  │
│  └──────┬───────┘           └──────▲───────┘                  │
│         │                          │                           │
└─────────┼──────────────────────────┼───────────────────────────┘
          │                          │
          ▼                          │
┌─────────────────┐         ┌───────────────┐
│  Stateless      │         │  OAuth        │
│  State Store    │         │  Provider     │
│  (Redis/DB)     │         │  (Google/     │
│                 │         │   GitHub)     │
│  Key: state     │         │               │
│  Value: {       │         └───────▲───────┘
│    redirect_uri │                 │
│  }              │                 │
│  TTL: 5 min     │         ┌───────┴───────┐
└─────────────────┘         │  User         │
                            │  Browser      │
                            └───────────────┘
```

### Client-Specific Flows

#### Web Client Flow

```
[Web Frontend]
     │ (GET /oauth/google/authorize)
     ├─ redirect_uri: https://any-llm.ai/auth/google/callback
     ↓
[OAuth Backend]
     │ - Generate state
     │ - Store: redis[state] = {redirect_uri: "https://..."}
     ↓
[User Browser → Google → Callback URL]
     ↓
[OAuth Backend /callback]
     │ - Validate state from Redis
     │ - Exchange code for tokens
     │ - Return JWT to web frontend
     ↓
[Web Frontend] (authenticated)
```

#### CLI Client Flow

```
[CLI Application]
     │ (Start local callback server on localhost:8080)
     │ (GET /oauth/google/authorize?redirect_uri=http://localhost:8080/callback)
     ↓
[OAuth Backend]
     │ - Validate redirect_uri in allowed list
     │ - Generate state
     │ - Store: redis[state] = {redirect_uri: "http://localhost:8080/callback"}
     ↓
[CLI opens browser → Google → Callback to localhost:8080]
     ↓
[CLI Callback Server]
     │ - Receives authorization code
     │ - Sends code to backend
     ↓
[OAuth Backend /callback]
     │ - Validate state from Redis
     │ - Exchange code for tokens
     │ - Return JWT to CLI
     ↓
[CLI Application] (authenticated)
```

## Architectural Patterns

### Pattern 1: Multiple Redirect URIs with Stateless State (Recommended)

**Architecture:**
- Authorization endpoint accepts `redirect_uri` as parameter
- State stored in external datastore (Redis/database) instead of session
- State record includes associated `redirect_uri` for validation
- Callback endpoint validates state-URI pair atomically

**Key Design Decisions:**

| Decision | Rationale |
|----------|-----------|
| Stateless state storage | Removes session/cookie dependency, enables CLI support |
| Explicit redirect_uri allowlist | Security: prevents open redirect attacks |
| Redis with TTL | Simple, scalable, automatic expiration |
| State tied to redirect_uri | Security: prevents state reuse across different URIs |
| Single-use state tokens | Security: prevents replay attacks |

**Security Properties:**
- ✅ CSRF protection via state parameter
- ✅ Authorization code interception prevention (PKCE optional but recommended)
- ✅ Redirect URI validation against explicit allowlist
- ✅ Time-bound state tokens (5-minute expiration)
- ✅ Single-use state tokens (deleted after validation)
- ✅ No session fixation attacks (stateless)

**Scalability:**
- Horizontal scaling: No session affinity required
- State storage: O(1) Redis operations
- Cleanup: Automatic via TTL (no cleanup jobs needed)

**Redirect URI Allowlist Design:**
```
Production:
  - https://any-llm.ai/auth/google/callback    (Web)
  - https://any-llm.ai/auth/github/callback    (Web)
  - http://localhost:8080-8085/callback        (CLI - 6 ports)

Security Rules:
  - Exact string matching (no wildcards)
  - http://localhost/* allowed per OAuth 2.0 spec (RFC 8252)
  - All other URIs must use https://
  - No dynamic URI registration
```

---

### Pattern 2: Device Code Flow (Alternative)

**Architecture:**
- Backend proxies OAuth 2.0 Device Authorization Grant (RFC 8628)
- No redirect URIs needed
- User enters code on separate device/browser
- CLI polls backend for token

**Flow:**
```
[CLI] → [Backend: /device-code] → [OAuth Provider: device code request]
                                ↓
                          {device_code, user_code, verification_url}
                                ↓
[CLI displays code] ← ← ← ← ← ← ┘
     │
     │ (User opens browser, enters code)
     │
     │ (CLI polls: /device-token)
     ↓
[Backend polls Google] → [Eventual token grant]
                       ↓
                  [Return JWT]
```

**Key Design Decisions:**

| Decision | Rationale |
|----------|-----------|
| Device code flow | Designed for CLI/device scenarios without redirect |
| Polling mechanism | No callback server needed in CLI |
| Separate verification URL | Works on headless systems, SSH sessions |

**Security Properties:**
- ✅ No redirect URI attack surface
- ✅ Works without local server
- ✅ User explicitly authorizes device
- ✅ Code is short-lived and single-use

**Trade-offs:**
- ➖ Additional step: user must enter code manually
- ➖ Not all OAuth providers support device flow
- ➖ Polling introduces latency
- ➕ Works on truly headless systems (no browser access)
- ➕ Better for shared/remote systems

---

### Pattern 3: Separate CLI OAuth Application (Not Recommended)

**Architecture:**
- Register second OAuth application with provider ("any-llm CLI")
- CLI-specific client ID/secret
- Backend routes based on client type

**Why Not Recommended:**
- ❌ Doesn't solve fundamental architectural problem
- ❌ Doubles configuration overhead
- ❌ Still requires stateless state management
- ❌ Client secret exposure risk in distributed CLI
- ❌ Two applications to maintain and monitor

---

## Architectural Comparison

| Criterion | Pattern 1: Multi-Redirect | Pattern 2: Device Code | Pattern 3: Separate App |
|-----------|---------------------------|------------------------|-------------------------|
| **User Experience** | ⭐⭐⭐ Seamless | ⭐⭐ Manual code entry | ⭐⭐⭐ Seamless |
| **Security** | ⭐⭐⭐ High | ⭐⭐⭐ High | ⭐⭐ Medium (secret exposure) |
| **Implementation Complexity** | ⭐⭐⭐ Low | ⭐⭐ Medium | ⭐ High |
| **Provider Support** | ⭐⭐⭐ Universal | ⭐⭐ Partial | ⭐⭐⭐ Universal |
| **Headless Support** | ⭐⭐ Requires browser | ⭐⭐⭐ True headless | ⭐⭐ Requires browser |
| **Backward Compatibility** | ⭐⭐⭐ Full | ⭐⭐⭐ Full | ⭐⭐ Requires migration |
| **Scalability** | ⭐⭐⭐ Horizontal | ⭐⭐⭐ Horizontal | ⭐⭐⭐ Horizontal |
| **Maintenance** | ⭐⭐⭐ Single config | ⭐⭐ Extra endpoints | ⭐ Double config |

**Recommendation**: **Pattern 1** (Multiple Redirect URIs) for best balance of UX, security, and simplicity.

---

## Security Architecture

### Threat Model

**Threats Addressed:**
1. **CSRF Attacks**: State parameter prevents cross-site request forgery
2. **Authorization Code Interception**: Redirect URI validation ensures code goes to legitimate client
3. **Replay Attacks**: Single-use state tokens prevent reuse
4. **Session Fixation**: Stateless design eliminates session-based attacks
5. **Open Redirects**: Explicit allowlist prevents redirect to malicious sites

**Attack Scenarios Considered:**

| Attack | Mitigation |
|--------|------------|
| Attacker intercepts authorization code | Code bound to specific redirect_uri; must match during exchange |
| Attacker reuses state token | State deleted after first use; Redis enforces atomicity |
| Attacker provides malicious redirect_uri | Backend validates against explicit allowlist |
| Attacker performs CSRF via state manipulation | State cryptographically random (256-bit entropy) |
| Man-in-the-middle on localhost | OAuth spec allows http://localhost (user's machine is trusted boundary) |

### Security Boundaries

```
┌──────────────────────────────────────────────────┐
│  Trusted: User's Machine                         │
│                                                   │
│  ┌─────────────┐         ┌──────────────┐       │
│  │   Browser   │ ←────→  │ CLI + Local  │       │
│  │             │         │ Callback     │       │
│  │             │         │ Server       │       │
│  └──────┬──────┘         └──────┬───────┘       │
│         │                       │                │
└─────────┼───────────────────────┼────────────────┘
          │ HTTPS                 │ HTTPS
          ▼                       ▼
┌──────────────────────────────────────────────────┐
│  Untrusted: Internet                             │
│                                                   │
│  ┌─────────────────┐      ┌──────────────────┐  │
│  │ OAuth Provider  │      │  OAuth Backend   │  │
│  │ (Google/GitHub) │      │  (Platform API)  │  │
│  └─────────────────┘      └──────────────────┘  │
│                                                   │
└──────────────────────────────────────────────────┘
```

**Trust Assumptions:**
- User's local machine is trusted (localhost server in CLI)
- OAuth backend is trusted (our infrastructure)
- OAuth providers are trusted (Google, GitHub)
- Network between user and providers uses TLS

---

## Data Architecture

### State Record Schema

**Conceptual Model:**
```
State {
  id: string (state token, 32+ bytes urlsafe random)
  redirect_uri: string (validated redirect destination)
  created_at: timestamp
  expires_at: timestamp (created_at + 5 minutes)
}
```

**Storage Options:**

#### Option A: Redis (Recommended)
```
Key: oauth:state:{state_token}
Value: JSON {"redirect_uri": "...", "created_at": "..."}
TTL: 300 seconds (5 minutes)

Pros:
  - Automatic expiration via TTL
  - O(1) operations
  - No cleanup jobs needed
  - Simple key-value model

Cons:
  - Requires Redis infrastructure
```

#### Option B: Database
```
Table: oauth_states
Columns:
  - state (PK, VARCHAR 128)
  - redirect_uri (VARCHAR 255)
  - created_at (TIMESTAMP)
  - expires_at (TIMESTAMP, indexed)

Pros:
  - Uses existing database
  - Durable storage (survives restarts)
  - Query capabilities

Cons:
  - Requires cleanup job (DELETE WHERE expires_at < NOW())
  - Slightly slower than Redis
```

### Token Lifecycle

```
[State Token Lifecycle]

Created ─────→ Stored (TTL=5m) ─────→ Validated ─────→ Deleted
   ↓              ↓                       ↓                ↓
Generate     Redis/DB              Callback validates    Single-use
random       with TTL              state-URI match       enforced
256-bit

[JWT Token Lifecycle]

Issued ─────→ Stored in CLI config ─────→ Used in API calls ─────→ Expired
   ↓              ↓                             ↓                      ↓
Backend      ~/.any-llm/config.json      Authorization header    Refresh or
generates    (0600 perms)                Bearer {token}          re-authenticate
```

---

## Integration Architecture

### API Contract

**Authorization Endpoint:**
```
GET /oauth/{provider}/authorize
Query Parameters:
  - redirect_uri: string (optional, defaults to web callback)

Response:
  - authorization_url: string (redirect user here)
  - state: string (include in callback)

Security:
  - Validates redirect_uri against allowlist
  - Generates cryptographically random state
  - Stores state with redirect_uri (TTL: 5 minutes)
```

**Callback Endpoint:**
```
POST /oauth/{provider}/callback
Request Body:
  - code: string (authorization code from provider)
  - state: string (state from authorize response)
  - redirect_uri: string (must match stored value)

Response:
  - access_token: string (JWT for platform API)
  - token_type: "bearer"
  - user_email: string (optional)
  - is_new_user: boolean (optional)

Security:
  - Validates state from Redis/DB
  - Verifies redirect_uri matches stored value
  - Deletes state (single-use enforcement)
  - Exchanges code with OAuth provider
  - Issues JWT with user identity
```

### Client Integration Patterns

**Web Client:**
```
1. User clicks "Login with Google"
2. Frontend calls GET /oauth/google/authorize (no redirect_uri)
3. Frontend redirects user to authorization_url
4. User authenticates with Google
5. Google redirects to https://any-llm.ai/auth/google/callback?code=...&state=...
6. Frontend extracts code and state from URL
7. Frontend calls POST /oauth/google/callback with code, state, redirect_uri
8. Backend returns JWT
9. Frontend stores JWT, user is authenticated
```

**CLI Client:**
```
1. User runs: any-llm auth login --provider google
2. CLI starts local HTTP server on first available port (8080-8085)
3. CLI calls GET /oauth/google/authorize?redirect_uri=http://localhost:8080/callback
4. CLI opens browser to authorization_url
5. User authenticates with Google
6. Google redirects to http://localhost:8080/callback?code=...&state=...
7. CLI local server receives callback
8. CLI calls POST /oauth/google/callback with code, state, redirect_uri
9. Backend returns JWT
10. CLI stores JWT in ~/.any-llm/config.json (0600 permissions)
11. CLI shuts down local server, user is authenticated
```

---

## Migration Strategy

### Phase 1: Add CLI Support (Backward Compatible)

**Objective**: Enable CLI OAuth without breaking web frontend

**Changes:**
- Add Redis for state storage (keep session as fallback for web)
- Update authorize endpoint to accept optional `redirect_uri` parameter
- Update callback endpoint to validate from Redis if state not in session
- Register localhost redirect URIs with OAuth providers
- Deploy to production

**Testing:**
- ✅ Web frontend continues working (uses default redirect_uri)
- ✅ CLI can authenticate with explicit redirect_uri
- ✅ Both flows coexist

**Risk**: Low (additive changes only)

### Phase 2: Deprecate Session-Based State (Optional)

**Objective**: Simplify architecture by removing session dependency

**Changes:**
- Remove session state storage
- Make `redirect_uri` parameter required in authorize endpoint
- Update web frontend to explicitly pass redirect_uri
- Remove session middleware dependency

**Testing:**
- ✅ Web frontend sends redirect_uri explicitly
- ✅ CLI continues working
- ✅ No session cookies used

**Risk**: Medium (requires web frontend update)

---

## Scalability & Performance

### Horizontal Scaling

**Stateless Design Benefits:**
- No session affinity required
- Load balancer can route requests arbitrarily
- Auto-scaling works seamlessly
- No sticky session configuration needed

**State Store Considerations:**
- Redis: Shared state across all backend instances
- Cluster mode: Sharding by state key
- Replication: Read replicas for high availability

### Performance Characteristics

**Authorization Endpoint:**
- Redis write: ~1ms
- Total latency: <10ms
- Throughput: Limited by Redis (10K+ ops/sec)

**Callback Endpoint:**
- Redis read + delete: ~2ms
- OAuth provider token exchange: 100-500ms (external)
- User creation/lookup: 10-50ms
- Total latency: 150-600ms (dominated by provider exchange)

**Bottlenecks:**
- OAuth provider token exchange (external service)
- User database writes (for new users)

**Optimization Strategies:**
- Cache user lookups (email → user_id)
- Async user creation (return JWT before full user record exists)
- Connection pooling for OAuth provider requests

---

## Monitoring & Observability

### Key Metrics

**OAuth Flow Success Rate:**
- Metric: `oauth_authorize_requests_total` (counter)
- Metric: `oauth_callback_success_total` (counter)
- Metric: `oauth_callback_failure_total` (counter, labeled by reason)
- Alert: Success rate < 95%

**State Validation:**
- Metric: `oauth_state_validation_failures` (counter, labeled by reason)
- Reasons: expired, not_found, redirect_uri_mismatch, already_used
- Alert: Spike in validation failures (potential attack)

**Provider Health:**
- Metric: `oauth_provider_token_exchange_duration` (histogram)
- Metric: `oauth_provider_errors` (counter, labeled by provider and error_code)
- Alert: Provider latency > 2s or error rate > 1%

### Logging

**Authorization Request:**
```
level: INFO
message: "OAuth authorization requested"
fields:
  - provider: "google"
  - redirect_uri: "http://localhost:8080/callback"
  - state: "abc123..." (first 8 chars only)
  - client_ip: "1.2.3.4"
```

**Callback Success:**
```
level: INFO
message: "OAuth callback successful"
fields:
  - provider: "google"
  - user_email: "user@example.com"
  - is_new_user: false
  - duration_ms: 342
```

**Security Events:**
```
level: WARN
message: "OAuth state validation failed"
fields:
  - provider: "google"
  - reason: "redirect_uri_mismatch"
  - expected_uri: "http://localhost:8080/callback"
  - provided_uri: "http://evil.com/callback"
  - client_ip: "1.2.3.4"
```

---

## Summary

### Recommended Architecture

**Pattern**: Multiple Redirect URIs with Stateless State Management

**Key Components:**
1. **Stateless State Store**: Redis with TTL for OAuth state
2. **Dynamic Redirect URIs**: Support both web and localhost callbacks
3. **Explicit Allowlist**: Security via validated redirect URI list
4. **Backward Compatible**: Web frontend continues working unchanged

**Benefits:**
- ✅ Seamless CLI OAuth experience (automatic browser flow)
- ✅ Web frontend unaffected
- ✅ Horizontally scalable (no session affinity)
- ✅ Secure (explicit allowlist, single-use states, CSRF protection)
- ✅ Standard OAuth 2.0 compliance
- ✅ Simple implementation (~1 day effort)

**Trade-offs:**
- Requires Redis or similar state store
- Slightly more complex than pure session-based (but more scalable)
- CLI requires browser access (use Device Code Flow for headless)

### Next Steps

1. Review and approve architectural approach
2. Design detailed API specifications
3. Implement backend changes
4. Update API documentation
5. Test with web and CLI clients
6. Deploy to production
7. Monitor metrics and iterate
