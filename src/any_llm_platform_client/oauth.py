"""OAuth authentication flow implementation for any-llm CLI.

This module implements OAuth Authorization Code Flow for Google and GitHub authentication.
It starts a local callback server, opens the user's browser for authentication, and
exchanges the authorization code for a JWT access token.
"""

import http.server
import logging
import socket
import socketserver
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlparse

import httpx

from .exceptions import OAuthError

logger = logging.getLogger(__name__)

# Default ports to try for local callback server
# Use port 8080 first for consistency (helps with OAuth state validation)
DEFAULT_PORTS = [8080, 8081, 8082, 8083, 8084, 8085]

# Timeout for waiting for user to complete OAuth flow
OAUTH_TIMEOUT_SECONDS = 300  # 5 minutes


class OAuthProvider(str, Enum):
    """Supported OAuth providers."""

    GOOGLE = "google"
    GITHUB = "github"


@dataclass
class OAuthResult:
    """Result from OAuth authentication flow."""

    access_token: str  # JWT access token from backend
    token_type: str  # Usually "bearer"
    user_email: str | None = None
    is_new_user: bool = False


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback requests."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default HTTP server logging."""
        pass  # Don't log to stderr

    def do_GET(self) -> None:
        """Handle GET request from OAuth provider redirect."""
        try:
            # Parse query parameters
            parsed_url = urlparse(self.path)

            if parsed_url.path == "/callback":
                query_params = parse_qs(parsed_url.query)

                # Check for error
                if "error" in query_params:
                    error = query_params["error"][0]
                    error_description = query_params.get("error_description", ["Unknown error"])[0]
                    self.server.auth_error = f"{error}: {error_description}"  # type: ignore
                    self._send_error_response(error_description)
                    return

                # Extract authorization code and state
                code = query_params.get("code", [None])[0]
                state = query_params.get("state", [None])[0]

                if code:
                    self.server.auth_code = code  # type: ignore
                    self.server.auth_state = state  # type: ignore
                    self._send_success_response()
                else:
                    self.server.auth_error = "No authorization code received"  # type: ignore
                    self._send_error_response("No authorization code received")
            else:
                # Unknown path
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")

        except Exception as e:
            logger.error("Error in OAuth callback handler: %s", e)
            self.server.auth_error = str(e)  # type: ignore
            self._send_error_response(str(e))

    def _send_success_response(self) -> None:
        """Redirect to backend success page."""
        backend_url = getattr(self.server, "backend_url", "https://platform-api.any-llm.ai/api/v1")
        success_url = f"{backend_url}/oauth/cli/success"

        self.send_response(302)
        self.send_header("Location", success_url)
        self.end_headers()

    def _send_error_response(self, error_message: str) -> None:
        """Send error HTML page to browser."""
        self.send_response(400)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Failed</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                }}
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 400px;
                }}
                h1 {{
                    color: #f44336;
                    margin-bottom: 20px;
                }}
                p {{
                    color: #666;
                    line-height: 1.6;
                }}
                .error-icon {{
                    font-size: 60px;
                    color: #f44336;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">✗</div>
                <h1>Authentication Failed</h1>
                <p>{error_message}</p>
                <p>Please try again in the command line.</p>
            </div>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))


def find_available_port(ports: list[int] = DEFAULT_PORTS) -> int:
    """Find an available port from the list.

    Args:
        ports: List of ports to try (default: [8080, 8081, 8082, ...])

    Returns:
        Available port number

    Raises:
        OAuthError: If no ports are available
    """
    for port in ports:
        try:
            # Try to bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("localhost", port))
            sock.close()
            logger.debug("Found available port: %s", port)
            return port
        except OSError:
            logger.debug("Port %s is not available", port)
            continue

    raise OAuthError(f"No available ports found in range: {ports}")


def start_callback_server(port: int, backend_url: str) -> socketserver.TCPServer:
    """Start local HTTP server for OAuth callback.

    Args:
        port: Port number to listen on
        backend_url: Backend API URL for redirecting to success page

    Returns:
        Running TCPServer instance

    Raises:
        OAuthError: If server cannot be started
    """
    try:
        server = socketserver.TCPServer(("localhost", port), OAuthCallbackHandler)
        server.auth_code = None  # type: ignore
        server.auth_state = None  # type: ignore
        server.auth_error = None  # type: ignore
        server.backend_url = backend_url  # type: ignore

        # Run server in background thread
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        logger.debug("Started OAuth callback server on port %s", port)
        return server

    except Exception as e:
        raise OAuthError(f"Failed to start callback server: {e}") from e


def get_authorization_url(
    backend_url: str, provider: OAuthProvider, redirect_uri: str | None = None, client: httpx.Client | None = None
) -> tuple[str, str, httpx.Client]:
    """Get OAuth authorization URL from backend.

    Args:
        backend_url: Backend API base URL
        provider: OAuth provider (google or github)
        redirect_uri: Optional redirect URI for CLI OAuth (e.g., http://localhost:8080/callback)
        client: Optional httpx.Client to reuse (for session/cookie persistence)

    Returns:
        Tuple of (authorization_url, state, client) - client may contain session cookies

    Raises:
        OAuthError: If request fails
    """
    try:
        url = f"{backend_url}/oauth/{provider.value}/authorize"

        # Add redirect_uri as query parameter if provided
        params = {}
        if redirect_uri:
            params["redirect_uri"] = redirect_uri
            logger.debug("Requesting authorization URL from %s with redirect_uri=%s", url, redirect_uri)
        else:
            logger.debug("Requesting authorization URL from %s", url)

        # Use provided client or create new one
        if client is None:
            client = httpx.Client()

        response = client.get(url, params=params, timeout=10.0)
        response.raise_for_status()

        data = response.json()
        auth_url = data.get("authorization_url")
        state = data.get("state")

        if not auth_url:
            raise OAuthError("Backend did not return authorization URL")

        logger.debug("Received authorization URL from backend (session cookies saved)")
        return auth_url, state, client

    except httpx.HTTPError as e:
        raise OAuthError(f"Failed to get authorization URL: {e}") from e
    except (KeyError, ValueError) as e:
        raise OAuthError(f"Invalid response from backend: {e}") from e


def exchange_code_for_token(
    backend_url: str,
    provider: OAuthProvider,
    code: str,
    redirect_uri: str,
    client: httpx.Client,
    state: str | None = None,
) -> dict[str, object]:
    """Exchange authorization code for access token.

    Args:
        backend_url: Backend API base URL
        provider: OAuth provider (google or github)
        code: Authorization code from OAuth provider
        redirect_uri: Redirect URI used in authorization request
        client: httpx.Client with session cookies from authorize call
        state: State parameter from OAuth callback (may be needed even if not in spec)

    Returns:
        Dictionary with access_token, token_type, and is_new_user

    Raises:
        OAuthError: If exchange fails
    """
    try:
        url = f"{backend_url}/oauth/{provider.value}/callback"
        logger.debug("Exchanging authorization code at %s", url)

        # Build payload - include state if provided (some backends need it)
        payload = {"code": code, "redirect_uri": redirect_uri}
        if state:
            payload["state"] = state
            logger.debug("Including state parameter in callback request")

        response = client.post(
            url,
            json=payload,
            timeout=30.0,
        )
        response.raise_for_status()

        data = response.json()

        if "access_token" not in data:
            raise OAuthError("Backend did not return access token")

        logger.debug("Successfully exchanged code for access token")
        return data

    except httpx.HTTPError as e:
        try:
            if hasattr(e, "response") and e.response is not None:  # type: ignore
                error_detail = e.response.json()  # type: ignore
                error_msg = error_detail.get("detail", str(e))
                # Log the full error for debugging
                logger.error("Backend error response: %s", error_detail)
            else:
                error_msg = str(e)
        except Exception:
            error_msg = str(e)
        raise OAuthError(f"Failed to exchange authorization code: {error_msg}") from e
    except (KeyError, ValueError) as e:
        raise OAuthError(f"Invalid response from backend: {e}") from e


def wait_for_callback(server: socketserver.TCPServer, timeout: int = OAUTH_TIMEOUT_SECONDS) -> tuple[str, str | None]:
    """Wait for OAuth callback with authorization code.

    Args:
        server: Running callback server
        timeout: Timeout in seconds (default: 300)

    Returns:
        Tuple of (authorization_code, state)

    Raises:
        OAuthError: If timeout occurs or error received
    """
    start_time = time.time()

    while True:
        # Check for successful callback
        if hasattr(server, "auth_code") and server.auth_code:  # type: ignore
            code = server.auth_code  # type: ignore
            state = getattr(server, "auth_state", None)
            logger.debug("Received authorization code from callback")
            return code, state

        # Check for error callback
        if hasattr(server, "auth_error") and server.auth_error:  # type: ignore
            error = server.auth_error  # type: ignore
            logger.error("OAuth error: %s", error)
            raise OAuthError(f"OAuth authentication failed: {error}")

        # Check timeout
        if time.time() - start_time > timeout:
            raise OAuthError(f"OAuth authentication timed out after {timeout} seconds")

        # Sleep briefly to avoid busy waiting
        time.sleep(0.5)


def open_browser(url: str, on_failure: Callable[[str], None] | None = None) -> bool:
    """Open URL in user's default browser.

    Args:
        url: URL to open
        on_failure: Optional callback function to call if browser fails to open

    Returns:
        True if browser opened successfully, False otherwise
    """
    try:
        logger.debug("Opening browser to: %s", url)
        success = webbrowser.open(url)

        if not success and on_failure:
            on_failure(url)

        return success

    except Exception as e:
        logger.warning("Failed to open browser: %s", e)
        if on_failure:
            on_failure(url)
        return False


def run_oauth_flow(
    backend_url: str,
    provider: OAuthProvider,
    on_browser_open: Callable[[str], None] | None = None,
    on_browser_failure: Callable[[str], None] | None = None,
) -> OAuthResult:
    """Run complete OAuth authentication flow.

    This function:
    1. Finds an available port and starts local callback server
    2. Gets authorization URL from backend
    3. Opens browser for user authentication
    4. Waits for callback with authorization code
    5. Exchanges code for access token
    6. Returns OAuthResult with token

    Args:
        backend_url: Backend API base URL
        provider: OAuth provider (google or github)
        on_browser_open: Optional callback when browser opens successfully
        on_browser_failure: Optional callback when browser fails to open

    Returns:
        OAuthResult with access token and user info

    Raises:
        OAuthError: If OAuth flow fails at any step
    """
    server = None
    http_client = None

    try:
        # 1. Find available port and start callback server
        port = find_available_port()
        redirect_uri = f"http://localhost:{port}/callback"
        server = start_callback_server(port, backend_url)

        # 2. Get authorization URL from backend (pass redirect_uri for CLI OAuth)
        auth_url, expected_state, http_client = get_authorization_url(backend_url, provider, redirect_uri=redirect_uri)

        # 3. Open browser for authentication
        if on_browser_open:
            on_browser_open(auth_url)

        browser_opened = open_browser(auth_url, on_failure=on_browser_failure)

        if not browser_opened:
            logger.warning("Failed to automatically open browser")
            # Continue anyway - user might open manually

        # 4. Wait for callback
        code, received_state = wait_for_callback(server)

        # 5. Validate state parameter (CSRF protection)
        if expected_state and received_state != expected_state:
            raise OAuthError(f"State parameter mismatch. Expected: {expected_state}, Received: {received_state}")

        # 6. Exchange code for token (uses same session, includes state)
        token_data = exchange_code_for_token(backend_url, provider, code, redirect_uri, http_client, received_state)

        # 7. Create result
        access_token = token_data["access_token"]
        assert isinstance(access_token, str), "access_token must be a string"
        token_type = token_data.get("token_type", "bearer")
        assert isinstance(token_type, str), "token_type must be a string"
        user_email = token_data.get("user_email")
        assert user_email is None or isinstance(user_email, str), "user_email must be None or string"
        is_new_user = token_data.get("is_new_user", False)
        assert isinstance(is_new_user, bool), "is_new_user must be a boolean"

        result = OAuthResult(
            access_token=access_token,
            token_type=token_type,
            user_email=user_email,
            is_new_user=is_new_user,
        )

        logger.info("OAuth authentication successful for provider: %s", provider.value)
        return result

    except OAuthError:
        raise
    except Exception as e:
        logger.error("Unexpected error during OAuth flow: %s", e)
        raise OAuthError(f"Unexpected error: {e}") from e
    finally:
        # Always cleanup resources
        if server:
            try:
                server.shutdown()
                server.server_close()
                logger.debug("Stopped OAuth callback server")
            except Exception as e:
                logger.warning("Error stopping callback server: %s", e)

        if http_client:
            try:
                http_client.close()
                logger.debug("Closed HTTP client")
            except Exception as e:
                logger.warning("Error closing HTTP client: %s", e)


def get_available_providers(backend_url: str) -> list[dict[str, object]]:
    """Get list of available OAuth providers from backend.

    Args:
        backend_url: Backend API base URL

    Returns:
        List of provider dictionaries with name, display_name, and enabled status

    Raises:
        OAuthError: If request fails
    """
    try:
        url = f"{backend_url}/oauth/providers"
        logger.debug("Fetching available OAuth providers from %s", url)

        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()

        data = response.json()
        providers = data.get("providers", [])

        # Filter to only enabled providers
        enabled_providers = [p for p in providers if p.get("enabled", False)]

        logger.debug("Found %s enabled OAuth providers", len(enabled_providers))
        return enabled_providers

    except httpx.HTTPError as e:
        raise OAuthError(f"Failed to get OAuth providers: {e}") from e
    except (KeyError, ValueError) as e:
        raise OAuthError(f"Invalid response from backend: {e}") from e
