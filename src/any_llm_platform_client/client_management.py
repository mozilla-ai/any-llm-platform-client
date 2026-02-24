"""Management methods extension for AnyLLMPlatformClient."""

import contextlib
import logging
import time
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

# Token expiry configuration
TOKEN_EXPIRY_SAFETY_MARGIN_HOURS = 23


class AuthenticationError(Exception):
    """Exception raised for authentication failures."""

    pass


class ManagementMixin:
    """Mixin class providing management methods for projects, providers, budgets, and clients."""

    # ========== Helper Methods ==========

    def _check_response(
        self, response: httpx.Response, operation: str, expected_codes: tuple[int, ...] = (200,)
    ) -> None:
        """Check HTTP response status and raise appropriate error.

        Args:
            response: HTTP response object
            operation: Description of operation (e.g., "list projects")
            expected_codes: Tuple of expected success status codes

        Raises:
            AuthenticationError: If status code is not in expected_codes
        """
        if response.status_code not in expected_codes:
            error_msg = f"Failed to {operation} (status: {response.status_code})"
            try:
                error_detail = response.json()
                if "detail" in error_detail:
                    error_msg += f": {error_detail['detail']}"
            except Exception:
                pass
            raise AuthenticationError(error_msg)

    # ========== Authentication Methods ==========

    def login(self, username: str, password: str) -> str:
        """Login with username and password to get an access token.

        Args:
            username: User's email or username
            password: User's password

        Returns:
            JWT access token string

        Raises:
            AuthenticationError: If login fails
        """
        logger.debug("🔐 Logging in...")
        start_time = time.perf_counter()

        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/login/access-token",
                data={"username": username, "password": password},
            )

        try:
            self._check_response(response, "login")
        except AuthenticationError:
            logger.error("Login failed: %s", response.status_code)
            with contextlib.suppress(ValueError):
                logger.debug(response.json())
            raise

        data = response.json()
        access_token = data["access_token"]

        # Store token and set expiration (24 hours minus 1 hour safety margin)
        self.access_token = access_token
        self.token_expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_SAFETY_MARGIN_HOURS)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Login successful (%.2fms)", elapsed_ms)
        return access_token

    # ========== Project Management Methods ==========

    def list_projects(self, skip: int = 0, limit: int = 100) -> dict:
        """List all projects for the authenticated user.

        Args:
            skip: Number of projects to skip (pagination)
            limit: Maximum number of projects to return

        Returns:
            Dictionary containing project list and count

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("📋 Listing projects...")
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/",
                headers={"Authorization": f"Bearer {self.access_token}"},
                params={"skip": skip, "limit": limit},
            )

        self._check_response(response, "list projects")
        return response.json()

    def create_project(self, name: str, description: str | None = None, encryption_key: str | None = None) -> dict:
        """Create a new project.

        Args:
            name: Project name (max 255 characters)
            description: Optional project description (max 1024 characters)
            encryption_key: Optional encryption key

        Returns:
            Dictionary containing the created project

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("➕ Creating project: %s", name)
        payload = {"name": name}
        if description:
            payload["description"] = description
        if encryption_key:
            payload["encryption_key"] = encryption_key

        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/projects/",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json=payload,
            )

        self._check_response(response, "create project", (200, 201))
        return response.json()

    def get_project(self, project_id: str) -> dict:
        """Get a specific project by ID.

        Args:
            project_id: UUID of the project

        Returns:
            Dictionary containing the project details

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🔍 Getting project: %s", project_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "get project")

        return response.json()

    def update_project(
        self,
        project_id: str,
        name: str | None = None,
        description: str | None = None,
        encryption_key: str | None = None,
    ) -> dict:
        """Update a project.

        Args:
            project_id: UUID of the project
            name: Optional new name (max 255 characters)
            description: Optional new description (max 1024 characters)
            encryption_key: Optional new encryption key

        Returns:
            Dictionary containing the updated project

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("✏️  Updating project: %s", project_id)
        payload = {}
        if name is not None:
            payload["name"] = name
        if description is not None:
            payload["description"] = description
        if encryption_key is not None:
            payload["encryption_key"] = encryption_key

        with httpx.Client() as client:
            response = client.patch(
                f"{self.any_llm_platform_url}/projects/{project_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json=payload,
            )

        self._check_response(response, "update project")

        return response.json()

    def delete_project(self, project_id: str) -> dict:
        """Delete a project.

        Args:
            project_id: UUID of the project

        Returns:
            Dictionary containing success message

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🗑️  Deleting project: %s", project_id)
        with httpx.Client() as client:
            response = client.delete(
                f"{self.any_llm_platform_url}/projects/{project_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "delete project")

        return response.json()

    # ========== Provider Key Management Methods ==========

    def list_provider_keys(self, project_id: str, include_archived: bool = False) -> dict:
        """List all provider keys for a project.

        Args:
            project_id: UUID of the project
            include_archived: Whether to include archived keys

        Returns:
            Dictionary containing provider key list and count

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🔑 Listing provider keys for project: %s", project_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/provider-keys/project/{project_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                params={"include_archived": include_archived},
            )

        self._check_response(response, "list provider keys")

        return response.json()

    def create_provider_key_mgmt(self, project_id: str, provider: str, encrypted_key: str) -> dict:
        """Create a new provider key.

        Args:
            project_id: UUID of the project
            provider: Provider name (e.g., "openai", "anthropic")
            encrypted_key: Base64-encoded encrypted key (or "" for local providers)

        Returns:
            Dictionary containing the created provider key

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("➕ Creating provider key: %s for project: %s", provider, project_id)
        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/provider-keys/",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"project_id": project_id, "provider": provider, "encrypted_key": encrypted_key},
            )

        self._check_response(response, "create provider key", (200, 201))

        return response.json()

    def update_provider_key_mgmt(self, provider_key_id: str, encrypted_key: str | None) -> dict:
        """Update a provider key.

        Args:
            provider_key_id: UUID of the provider key
            encrypted_key: New encrypted key value (or None to clear)

        Returns:
            Dictionary containing the updated provider key

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("✏️  Updating provider key: %s", provider_key_id)
        with httpx.Client() as client:
            response = client.patch(
                f"{self.any_llm_platform_url}/provider-keys/{provider_key_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"encrypted_key": encrypted_key},
            )

        self._check_response(response, "update provider key")

        return response.json()

    def delete_provider_key_mgmt(self, provider_key_id: str, permanent: bool = False) -> dict:
        """Delete or archive a provider key.

        Args:
            provider_key_id: UUID of the provider key
            permanent: If False, archive only. If True, permanently delete.

        Returns:
            Dictionary containing success message

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        action = "Deleting" if permanent else "Archiving"
        logger.debug("🗑️  %s provider key: %s", action, provider_key_id)
        with httpx.Client() as client:
            response = client.delete(
                f"{self.any_llm_platform_url}/provider-keys/{provider_key_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                params={"permanent": permanent},
            )

        self._check_response(response, "delete provider key")

        return response.json()

    def unarchive_provider_key(self, provider_key_id: str) -> dict:
        """Unarchive a provider key.

        Args:
            provider_key_id: UUID of the provider key

        Returns:
            Dictionary containing the unarchived provider key

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("📦 Unarchiving provider key: %s", provider_key_id)
        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/provider-keys/{provider_key_id}/unarchive",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "unarchive provider key")

        return response.json()

    # ========== Budget Management Methods ==========

    def list_project_budgets(self, project_id: str) -> dict:
        """List all budgets for a project.

        Args:
            project_id: UUID of the project

        Returns:
            Dictionary containing budget list and count

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("💰 Listing budgets for project: %s", project_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}/budgets",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "list project budgets")

        return response.json()

    def create_project_budget(self, project_id: str, budget_limit: float, spend_period: str = "monthly") -> dict:
        """Create a project budget.

        Args:
            project_id: UUID of the project
            budget_limit: Budget limit amount
            spend_period: One of "daily", "weekly", "monthly"

        Returns:
            Dictionary containing the created budget

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("➕ Creating %s budget for project: %s", spend_period, project_id)
        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/projects/{project_id}/budgets",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"budget_limit": budget_limit, "spend_period": spend_period},
            )

        self._check_response(response, "create project budget", (201,))

        return response.json()

    def get_project_budget(self, project_id: str, spend_period: str) -> dict:
        """Get a specific project budget.

        Args:
            project_id: UUID of the project
            spend_period: One of "daily", "weekly", "monthly"

        Returns:
            Dictionary containing the budget details

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🔍 Getting %s budget for project: %s", spend_period, project_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}/budgets/{spend_period}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "get project budget")

        return response.json()

    def update_project_budget(self, project_id: str, spend_period: str, budget_limit: float) -> dict:
        """Update a project budget.

        Args:
            project_id: UUID of the project
            spend_period: One of "daily", "weekly", "monthly"
            budget_limit: New budget limit amount

        Returns:
            Dictionary containing the updated budget

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("✏️  Updating %s budget for project: %s", spend_period, project_id)
        with httpx.Client() as client:
            response = client.patch(
                f"{self.any_llm_platform_url}/projects/{project_id}/budgets/{spend_period}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"budget_limit": budget_limit},
            )

        self._check_response(response, "update project budget")

        return response.json()

    def delete_project_budget(self, project_id: str, spend_period: str) -> dict:
        """Delete a project budget.

        Args:
            project_id: UUID of the project
            spend_period: One of "daily", "weekly", "monthly"

        Returns:
            Dictionary containing success message

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🗑️  Deleting %s budget for project: %s", spend_period, project_id)
        with httpx.Client() as client:
            response = client.delete(
                f"{self.any_llm_platform_url}/projects/{project_id}/budgets/{spend_period}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "delete project budget")

        return response.json()

    # ========== Client Management Methods ==========

    def list_clients(self, project_id: str, skip: int = 0, limit: int = 100) -> dict:
        """List all clients for a project.

        Args:
            project_id: UUID of the project
            skip: Number of clients to skip (pagination)
            limit: Maximum number of clients to return

        Returns:
            Dictionary containing client list and count

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("👥 Listing clients for project: %s", project_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/",
                headers={"Authorization": f"Bearer {self.access_token}"},
                params={"skip": skip, "limit": limit},
            )

        self._check_response(response, "list clients")

        return response.json()

    def create_client(self, project_id: str, name: str, is_default: bool = False) -> dict:
        """Create a new client.

        Args:
            project_id: UUID of the project
            name: Client name (max 255 characters)
            is_default: Whether this should be the default client

        Returns:
            Dictionary containing the created client

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("➕ Creating client: %s for project: %s", name, project_id)
        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"name": name, "is_default": is_default},
            )

        self._check_response(response, "create client", (200, 201))

        return response.json()

    def get_client(self, project_id: str, client_id: str) -> dict:
        """Get a specific client.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client

        Returns:
            Dictionary containing the client details

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🔍 Getting client: %s", client_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "get client")

        return response.json()

    def update_client(
        self, project_id: str, client_id: str, name: str | None = None, is_default: bool | None = None
    ) -> dict:
        """Update a client.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client
            name: Optional new name
            is_default: Optional new default status

        Returns:
            Dictionary containing the updated client

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("✏️  Updating client: %s", client_id)
        payload = {}
        if name is not None:
            payload["name"] = name
        if is_default is not None:
            payload["is_default"] = is_default

        with httpx.Client() as client:
            response = client.patch(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json=payload,
            )

        self._check_response(response, "update client")

        return response.json()

    def delete_client(self, project_id: str, client_id: str) -> dict:
        """Delete a client.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client

        Returns:
            Dictionary containing success message

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🗑️  Deleting client: %s", client_id)
        with httpx.Client() as client:
            response = client.delete(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "delete client")

        return response.json()

    def set_default_client(self, project_id: str, client_id: str) -> dict:
        """Set a client as the default for a project.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client

        Returns:
            Dictionary containing the updated client

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("⭐ Setting client %s as default", client_id)
        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}/set-default",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "set default client")

        return response.json()

    def list_client_budgets(self, project_id: str, client_id: str) -> list:
        """List all budgets for a client.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client

        Returns:
            List of client budget dictionaries

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("💰 Listing budgets for client: %s", client_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}/budgets/",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "list client budgets")

        return response.json()

    def create_client_budget(self, project_id: str, client_id: str, budget_limit: float, spend_period: str) -> dict:
        """Create a client budget.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client
            budget_limit: Budget limit amount
            spend_period: One of "daily", "weekly", "monthly"

        Returns:
            Dictionary containing the created budget

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("➕ Creating %s budget for client: %s", spend_period, client_id)
        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}/budgets/",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"budget_limit": budget_limit, "spend_period": spend_period},
            )

        self._check_response(response, "create client budget", (201,))

        return response.json()

    def get_client_budget(self, project_id: str, client_id: str, spend_period: str) -> dict:
        """Get a specific client budget.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client
            spend_period: One of "daily", "weekly", "monthly"

        Returns:
            Dictionary containing the budget details

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🔍 Getting %s budget for client: %s", spend_period, client_id)
        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}/budgets/{spend_period}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "get client budget")

        return response.json()

    def update_client_budget(self, project_id: str, client_id: str, spend_period: str, budget_limit: float) -> dict:
        """Update a client budget.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client
            spend_period: One of "daily", "weekly", "monthly"
            budget_limit: New budget limit amount

        Returns:
            Dictionary containing the updated budget

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("✏️  Updating %s budget for client: %s", spend_period, client_id)
        with httpx.Client() as client:
            response = client.patch(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}/budgets/{spend_period}",
                headers={"Authorization": f"Bearer {self.access_token}"},
                json={"budget_limit": budget_limit},
            )

        self._check_response(response, "update client budget")

        return response.json()

    def delete_client_budget(self, project_id: str, client_id: str, spend_period: str) -> dict:
        """Delete a client budget.

        Args:
            project_id: UUID of the project
            client_id: UUID of the client
            spend_period: One of "daily", "weekly", "monthly"

        Returns:
            Dictionary containing success message

        Raises:
            AuthenticationError: If not authenticated or token invalid
        """
        if not self.access_token:
            raise AuthenticationError("Not authenticated. Call login() first.")

        logger.debug("🗑️  Deleting %s budget for client: %s", spend_period, client_id)
        with httpx.Client() as client:
            response = client.delete(
                f"{self.any_llm_platform_url}/projects/{project_id}/clients/{client_id}/budgets/{spend_period}",
                headers={"Authorization": f"Bearer {self.access_token}"},
            )

        self._check_response(response, "delete client budget")

        return response.json()
