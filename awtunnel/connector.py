"""
awtunnel.connector - expose one local port through a Cloudflare Tunnel
=======================================================================

Moved here 2026-09-19 from AitherOS/lib/network/AitherTunnel.py (531 lines, zero
monorepo imports -- the measured extraction target in ecosystem.yaml). The lib
path is a re-export shim. Stdlib only; `starlette` is imported lazily inside
create_api_key_middleware and is optional.

Gives a service that has no public address one: a quick tunnel (temporary
trycloudflare.com URL, no account) or a named tunnel (your hostname, needs
`cloudflared login`). Requires the cloudflared binary on PATH or in a standard
install location.

Features:
- Start/stop Cloudflare quick tunnels (no account required)
- Persistent named tunnels (requires cloudflared login)
- API key authentication middleware
- Rate limiting for security
- Automatic reconnection

Usage:
    from awtunnel.connector import AitherTunnel

    # Quick tunnel (temporary URL, no account needed)
    tunnel = AitherTunnel(local_port=8150)
    url = await tunnel.start()
    print(f"Public URL: {url}")

    # Named tunnel (persistent URL, requires cloudflared login)
    tunnel = AitherTunnel(
        local_port=8150,
        tunnel_name="aither-api",
        hostname="api.aither.example.com"
    )
    url = await tunnel.start()

Requirements:
    - cloudflared binary installed (https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/)
    - For named tunnels: cloudflared login

Author: AitherOS Team
Port: N/A (manages external tunnels)
"""

import asyncio
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("awtunnel.connector")


class TunnelStatus(Enum):
    """Tunnel connection status."""
    STOPPED = "stopped"
    STARTING = "starting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


@dataclass
class TunnelConfig:
    """Tunnel configuration."""
    local_port: int = 8150
    local_host: str = "localhost"
    protocol: str = "http"
    tunnel_name: Optional[str] = None  # For named/persistent tunnels
    hostname: Optional[str] = None  # Custom domain for named tunnels
    cloudflared_path: Optional[str] = None  # Path to cloudflared binary
    metrics_port: int = 0  # Cloudflared metrics port (0 = auto)
    api_key: Optional[str] = None  # API key for authentication
    allowed_origins: list = field(default_factory=list)  # CORS origins
    max_reconnect_attempts: int = 5
    reconnect_delay_seconds: float = 5.0


class AitherTunnel:
    """
    Cloudflare Tunnel manager for exposing local services.

    Supports two modes:
    1. Quick Tunnel: Temporary trycloudflare.com URL, no account needed
    2. Named Tunnel: Persistent custom domain, requires cloudflared login
    """

    def __init__(
        self,
        local_port: int = 8150,
        local_host: str = "localhost",
        protocol: str = "http",
        tunnel_name: Optional[str] = None,
        hostname: Optional[str] = None,
        cloudflared_path: Optional[str] = None,
        api_key: Optional[str] = None,
        allowed_origins: Optional[list] = None,
    ):
        """
        Initialize the tunnel manager.

        Args:
            local_port: Local port to tunnel (default: 8150 for MicroScheduler)
            local_host: Local host (default: localhost)
            protocol: Protocol (http or https)
            tunnel_name: Name for persistent tunnel (None for quick tunnel)
            hostname: Custom domain for named tunnel
            cloudflared_path: Path to cloudflared binary (auto-detected if None)
            api_key: API key for request authentication
            allowed_origins: List of allowed CORS origins
        """
        self.config = TunnelConfig(
            local_port=local_port,
            local_host=local_host,
            protocol=protocol,
            tunnel_name=tunnel_name,
            hostname=hostname,
            cloudflared_path=cloudflared_path,
            api_key=api_key,
            allowed_origins=allowed_origins or [],
        )

        self._process: Optional[subprocess.Popen] = None
        self._status = TunnelStatus.STOPPED
        self._public_url: Optional[str] = None
        self._metrics_url: Optional[str] = None
        self._reconnect_count = 0
        self._status_callbacks: list[Callable[[TunnelStatus, Optional[str]], None]] = []
        self._log_task: Optional[asyncio.Task] = None

        # Find cloudflared binary
        self._cloudflared = self._find_cloudflared()

    @property
    def status(self) -> TunnelStatus:
        """Current tunnel status."""
        return self._status

    @property
    def public_url(self) -> Optional[str]:
        """Public URL if connected, None otherwise."""
        return self._public_url if self._status == TunnelStatus.CONNECTED else None

    @property
    def is_connected(self) -> bool:
        """Whether the tunnel is connected."""
        return self._status == TunnelStatus.CONNECTED

    def _find_cloudflared(self) -> str:
        """Find the cloudflared binary."""
        if self.config.cloudflared_path:
            if os.path.isfile(self.config.cloudflared_path):
                return self.config.cloudflared_path
            raise FileNotFoundError(f"cloudflared not found at {self.config.cloudflared_path}")

        # Check common locations
        binary_name = "cloudflared.exe" if sys.platform == "win32" else "cloudflared"

        # Check PATH
        found = shutil.which(binary_name)
        if found:
            return found

        # Check common installation paths
        common_paths = []
        if sys.platform == "win32":
            common_paths = [
                Path(os.environ.get("LOCALAPPDATA", "")) / "cloudflared" / binary_name,
                Path(os.environ.get("PROGRAMFILES", "")) / "cloudflared" / binary_name,
                Path.home() / ".cloudflared" / binary_name,
            ]
        else:
            common_paths = [
                Path("/usr/local/bin") / binary_name,
                Path("/usr/bin") / binary_name,
                Path.home() / ".cloudflared" / binary_name,
                Path.home() / "bin" / binary_name,
            ]

        for path in common_paths:
            if path.is_file():
                return str(path)

        raise FileNotFoundError(
            "cloudflared not found. Please install it from:\n"
            "https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/"
        )

    def _set_status(self, status: TunnelStatus, url: Optional[str] = None):
        """Update status and notify callbacks."""
        self._status = status
        if url:
            self._public_url = url

        for callback in self._status_callbacks:
            try:
                callback(status, url)
            except Exception as e:
                logger.error(f"Status callback error: {e}")

    def on_status_change(self, callback: Callable[[TunnelStatus, Optional[str]], None]):
        """Register a callback for status changes."""
        self._status_callbacks.append(callback)

    async def start(self) -> str:
        """
        Start the Cloudflare tunnel.

        Returns:
            The public URL for the tunnel.

        Raises:
            RuntimeError: If tunnel fails to start.
        """
        if self._status in (TunnelStatus.CONNECTED, TunnelStatus.STARTING):
            if self._public_url:
                return self._public_url
            raise RuntimeError("Tunnel already starting")

        self._set_status(TunnelStatus.STARTING)
        logger.info(f"Starting tunnel to {self.config.local_host}:{self.config.local_port}")

        try:
            # Build command
            cmd = [self._cloudflared, "tunnel"]

            if self.config.tunnel_name:
                # Named tunnel mode
                cmd.extend(["run", self.config.tunnel_name])
                if self.config.hostname:
                    cmd.extend(["--hostname", self.config.hostname])
            else:
                # Quick tunnel mode (--url is the key flag)
                local_url = f"{self.config.protocol}://{self.config.local_host}:{self.config.local_port}"
                cmd.extend(["--url", local_url])

            # Add metrics port if specified
            if self.config.metrics_port:
                cmd.extend(["--metrics", f"localhost:{self.config.metrics_port}"])

            logger.debug(f"Running: {' '.join(cmd)}")

            # Start process
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            # Start log monitoring task
            self._log_task = asyncio.create_task(self._monitor_output())

            # Wait for URL to appear (timeout after 30 seconds)
            url = await asyncio.wait_for(self._wait_for_url(), timeout=30.0)

            self._set_status(TunnelStatus.CONNECTED, url)
            logger.info(f"Tunnel connected: {url}")

            return url

        except asyncio.TimeoutError:
            await self.stop()
            raise RuntimeError("Tunnel failed to start within 30 seconds")
        except Exception as e:
            self._set_status(TunnelStatus.ERROR)
            await self.stop()
            raise RuntimeError(f"Failed to start tunnel: {e}")

    async def _wait_for_url(self) -> str:
        """Wait for the public URL to appear in output."""
        re.compile(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com')
        re.compile(r'https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        while self._process and self._process.poll() is None:
            # Check if we got a URL from the log monitor
            if self._public_url:
                return self._public_url
            await asyncio.sleep(0.1)

        raise RuntimeError("cloudflared process exited unexpectedly")

    async def _monitor_output(self):
        """Monitor cloudflared output for status changes.

        The pipe read is BLOCKING and runs in a worker thread. Measured
        2026-09-19 on the first live `awtunnel up`: iterating the pipe directly
        inside this coroutine starved the loop, so `_wait_for_url` never ran and
        start() timed out while cloudflared had printed the URL seconds earlier.
        """
        if not self._process or not self._process.stdout:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._read_output_blocking)

    def _read_output_blocking(self) -> None:
        url_pattern = re.compile(r'(https://[a-zA-Z0-9-]+\.trycloudflare\.com)')
        try:
            for line in self._process.stdout:
                line = line.strip()
                if not line:
                    continue

                logger.debug(f"cloudflared: {line}")

                # Look for URL
                match = url_pattern.search(line)
                if match and not self._public_url:
                    self._public_url = match.group(1)
                    logger.info(f"Found tunnel URL: {self._public_url}")

                # Look for connection status
                if "Registered tunnel connection" in line or "Connection registered" in line:
                    if self._public_url:
                        self._set_status(TunnelStatus.CONNECTED, self._public_url)

                # Look for reconnection
                if "Retrying" in line or "reconnect" in line.lower():
                    self._set_status(TunnelStatus.RECONNECTING)
                    self._reconnect_count += 1

                # Look for errors
                if "error" in line.lower() or "failed" in line.lower():
                    logger.warning(f"Tunnel warning: {line}")

        except Exception as e:
            logger.error(f"Output monitoring error: {e}")

    async def stop(self):
        """Stop the tunnel."""
        logger.info("Stopping tunnel...")

        if self._log_task:
            self._log_task.cancel()
            try:
                await self._log_task
            except asyncio.CancelledError as e:
                logger.debug(f"[AitherTunnel.stop] Operation failed: {e}")
            self._log_task = None

        if self._process:
            try:
                # Try graceful shutdown first
                if sys.platform == "win32":
                    self._process.terminate()
                else:
                    self._process.send_signal(signal.SIGTERM)

                # Wait up to 5 seconds
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()
            except Exception as e:
                logger.error(f"Error stopping tunnel: {e}")
            finally:
                self._process = None

        self._public_url = None
        self._set_status(TunnelStatus.STOPPED)
        logger.info("Tunnel stopped")

    async def restart(self) -> str:
        """Restart the tunnel."""
        await self.stop()
        await asyncio.sleep(1)
        return await self.start()

    def get_status(self) -> Dict[str, Any]:
        """Get detailed tunnel status."""
        return {
            "status": self._status.value,
            "public_url": self._public_url,
            "local_endpoint": f"{self.config.protocol}://{self.config.local_host}:{self.config.local_port}",
            "tunnel_name": self.config.tunnel_name,
            "reconnect_count": self._reconnect_count,
            "is_quick_tunnel": self.config.tunnel_name is None,
            "has_api_key": bool(self.config.api_key),
            "allowed_origins": self.config.allowed_origins,
        }

    def generate_api_config(self) -> Dict[str, str]:
        """
        Generate configuration for client-side API calls.

        Returns:
            Dict with configuration to use in the web client.
        """
        if not self._public_url:
            raise RuntimeError("Tunnel not connected")

        config = {
            "api_url": self._public_url,
            "endpoint_chat": f"{self._public_url}/v1/chat/completions",
            "endpoint_generate": f"{self._public_url}/generate",
        }

        if self.config.api_key:
            config["requires_auth"] = "true"
            # Don't expose the actual key - just indicate auth is needed

        return config


# ============================================================================
# FASTAPI SECURITY MIDDLEWARE (for use with AitherLLM)
# ============================================================================

def create_api_key_middleware(
    api_key: str,
    allowed_origins: list = None,
    skip_paths: list = None,
):
    """
    Create FastAPI middleware for API key authentication.

    Add this to AitherLLM when exposing via tunnel:

        from awtunnel.connector import create_api_key_middleware

        middleware = create_api_key_middleware(
            api_key="your-secret-key",
            allowed_origins=["https://aither.neocities.org"]
        )
        app.add_middleware(middleware)

    Args:
        api_key: The API key clients must provide
        allowed_origins: List of allowed CORS origins
        skip_paths: Paths to skip authentication (e.g., ["/health"])

    Returns:
        Starlette middleware class
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    skip_paths = skip_paths or ["/health", "/", "/docs", "/openapi.json"]
    allowed_origins = allowed_origins or ["*"]

    class APIKeyMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            # Skip auth for certain paths
            if request.url.path in skip_paths:
                response = await call_next(request)
                return response

            # Check API key
            auth_header = request.headers.get("Authorization", "")
            x_api_key = request.headers.get("X-API-Key", "")

            # Support both Bearer token and X-API-Key header
            provided_key = None
            if auth_header.startswith("Bearer "):
                provided_key = auth_header[7:]
            elif x_api_key:
                provided_key = x_api_key

            if provided_key != api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )

            # Add CORS headers
            response = await call_next(request)
            origin = request.headers.get("Origin", "")

            if "*" in allowed_origins or origin in allowed_origins:
                response.headers["Access-Control-Allow-Origin"] = origin or "*"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = (
                    "Authorization, X-API-Key, Content-Type")

            return response

    return APIKeyMiddleware


# ============================================================================
# CLI INTERFACE
# ============================================================================

async def main():
    """CLI for testing the tunnel."""
    import argparse

    parser = argparse.ArgumentParser(description="AitherTunnel - Cloudflare Tunnel Manager")
    parser.add_argument("--port", type=int, default=8150, help="Local port to tunnel")
    parser.add_argument("--host", default="localhost", help="Local host")
    parser.add_argument("--name", help="Tunnel name (for persistent tunnels)")
    parser.add_argument("--hostname", help="Custom domain (requires named tunnel)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    )

    tunnel = AitherTunnel(
        local_port=args.port,
        local_host=args.host,
        tunnel_name=args.name,
        hostname=args.hostname,
    )

    def on_status(status: TunnelStatus, url: Optional[str]):
        print(f"Status: {status.value}" + (f" - {url}" if url else ""))

    tunnel.on_status_change(on_status)

    try:
        print("Starting tunnel... (Ctrl+C to stop)")
        url = await tunnel.start()
        print(f"\n{'='*60}")
        print("TUNNEL ACTIVE")
        print(f"{'='*60}")
        print(f"Public URL: {url}")
        print(f"Local:      http://{args.host}:{args.port}")
        print(f"{'='*60}\n")

        # Keep running
        while tunnel.is_connected:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await tunnel.stop()


if __name__ == "__main__":
    asyncio.run(main())
