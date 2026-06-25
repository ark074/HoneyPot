"""
AegisTrap HTTP Honeypot Service
=================================
Provides a realistic HTTP web server on ports 80 and 8080 using aiohttp.
Presents a mock corporate login panel and an exposed Apache/nginx status page.
Captures all GET/POST requests, headers, and paths for threat intelligence.
"""

import asyncio
import logging
import json
from typing import Optional, Callable, Awaitable
from urllib.parse import unquote_plus

from aiohttp import web

from config import (
    HTTP_PORT,
    HTTP_ALT_PORT,
    HTTP_SERVER_HEADER,
)
from aegistrap.core.session_manager import session_manager, ai_bridge
from aegistrap.core.pipeline import command_pipeline

logger = logging.getLogger("aegistrap.http")

# =============================================================================
# HTML Templates for the Honeypot Web Interface
# =============================================================================

CORPORATE_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CorpNet - Internal Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #1a1a2e;
            font-size: 24px;
            font-weight: 700;
        }
        .logo p {
            color: #666;
            font-size: 13px;
            margin-top: 5px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #333;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 6px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #0f3460;
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: #0f3460;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn-login:hover { background: #1a1a2e; }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #999;
            font-size: 12px;
        }
        .alert {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 10px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #856404;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>CorpNet Portal</h1>
            <p>Internal Systems Access - Authorized Personnel Only</p>
        </div>
        <div class="alert" id="alert">Invalid credentials. Please try again.</div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        <div class="footer">
            &copy; 2024 CorpNet Systems Inc. | IT Support: ext. 4501
        </div>
    </div>
</body>
</html>"""

SERVER_STATUS_PAGE = """<!DOCTYPE html>
<html>
<head><title>Apache Status</title></head>
<body>
<h1>Apache Server Status for corp-srv-prod-01.internal (via 10.0.4.17)</h1>
<dl>
<dt>Server Version: Apache/2.4.52 (Ubuntu)</dt>
<dt>Server MPM: event</dt>
<dt>Server Built: 2023-10-26T13:44:01</dt>
</dl>
<hr>
<dl>
<dt>Current Time: Thursday, 18-Jan-2024 14:35:22 UTC</dt>
<dt>Restart Time: Monday, 15-Jan-2024 03:00:01 UTC</dt>
<dt>Parent Server Config. Generation: 1</dt>
<dt>Parent Server MPM Generation: 0</dt>
<dt>Server uptime: 3 days 11 hours 35 minutes 21 seconds</dt>
<dt>Server load: 0.42 0.38 0.35</dt>
<dt>Total accesses: 142837 - Total Traffic: 2.1 GB</dt>
<dt>CPU Usage: u2.34 s1.02 cu0 cs0 - .00114% CPU load</dt>
<dt>0.478 requests/sec - 7.5 kB/second - 15.4 kB/request</dt>
<dt>3 requests currently being processed, 7 idle workers</dt>
</dl>
<pre>
___W_._W___................................................
................................................................
</pre>
<table border="0">
<tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>CPU</th><th>SS</th><th>Req</th><th>Conn</th><th>Child</th><th>Slot</th><th>Client</th><th>VHost</th><th>Request</th></tr>
<tr><td>0-0</td><td>1847</td><td>0/3421/142837</td><td>W</td><td>0.34</td><td>0</td><td>0</td><td>0.0</td><td>0.12</td><td>2.10</td><td>10.0.4.22</td><td>corp-srv-prod-01.internal</td><td>GET /api/v2/status HTTP/1.1</td></tr>
<tr><td>1-0</td><td>1849</td><td>0/2847/138201</td><td>_</td><td>0.28</td><td>4</td><td>0</td><td>0.0</td><td>0.09</td><td>1.87</td><td>10.0.4.5</td><td>corp-srv-prod-01.internal</td><td>GET /dashboard HTTP/1.1</td></tr>
<tr><td>2-0</td><td>1851</td><td>0/1923/98234</td><td>W</td><td>0.19</td><td>1</td><td>0</td><td>0.0</td><td>0.07</td><td>1.45</td><td>10.0.4.11</td><td>corp-srv-prod-01.internal</td><td>POST /api/v2/upload HTTP/1.1</td></tr>
</table>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at corp-srv-prod-01.internal Port 80</address>
</body>
</html>"""

ADMIN_PANEL_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - CorpNet</title>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }
        h1 { color: #0f0; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .info { margin: 10px 0; }
        .warn { color: #ff0; }
        pre { background: #000; padding: 15px; border: 1px solid #333; overflow-x: auto; }
        a { color: #0ff; }
    </style>
</head>
<body>
    <h1>[ADMIN] Server Management Console</h1>
    <div class="info">Hostname: corp-srv-prod-01</div>
    <div class="info">IP: 10.0.4.17</div>
    <div class="info">Kernel: 5.15.0-91-generic</div>
    <div class="info">Uptime: 3 days, 11:35</div>
    <div class="warn">[WARNING] 3 failed SSH login attempts in last hour</div>
    <hr>
    <h2>Recent Connections</h2>
    <pre>
tcp  0  0 10.0.4.17:3306   10.0.4.5:48292   ESTABLISHED  mysql
tcp  0  0 10.0.4.17:5432   10.0.4.8:52104   ESTABLISHED  postgres
tcp  0  0 10.0.4.17:6379   10.0.4.11:39281  ESTABLISHED  redis
tcp  0  0 10.0.4.17:22     10.0.4.1:61432   ESTABLISHED  sshd
    </pre>
    <h2>Database Credentials (rotate by EOD!)</h2>
    <pre>
MYSQL_HOST=10.0.4.5
MYSQL_USER=app_service
MYSQL_PASS=Pr0d_S3cur3!_2024
MYSQL_DB=corpnet_production

REDIS_URL=redis://:r3d1s_c@ch3@10.0.4.11:6379/0
    </pre>
    <div class="warn">[TODO] Move credentials to vault - ticket INFRA-2847</div>
</body>
</html>"""

NOT_FOUND_PAGE = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at corp-srv-prod-01.internal Port 80</address>
</body>
</html>"""

FORBIDDEN_PAGE = """<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at corp-srv-prod-01.internal Port 80</address>
</body>
</html>"""


class HTTPHoneypotHandler:
    """
    HTTP request handler for the honeypot web server.
    Routes requests to appropriate mock pages and captures all traffic.
    """

    def __init__(self, log_callback: Optional[Callable[..., Awaitable]] = None):
        self._log_callback = log_callback

    def create_app(self) -> web.Application:
        """Create and configure the aiohttp web application."""
        app = web.Application(
            middlewares=[self._server_header_middleware]
        )
        app.router.add_route("*", "/", self._handle_root)
        app.router.add_route("*", "/login", self._handle_login)
        app.router.add_route("*", "/server-status", self._handle_server_status)
        app.router.add_route("*", "/admin", self._handle_admin)
        app.router.add_route("*", "/admin/{path:.*}", self._handle_admin)
        app.router.add_route("*", "/api/{path:.*}", self._handle_api)
        app.router.add_route("*", "/wp-admin{path:.*}", self._handle_wordpress)
        app.router.add_route("*", "/wp-login{path:.*}", self._handle_wordpress)
        app.router.add_route("*", "/.env", self._handle_env)
        app.router.add_route("*", "/.git/{path:.*}", self._handle_git_exposure)
        app.router.add_route("*", "/robots.txt", self._handle_robots)
        app.router.add_route("*", "/{path:.*}", self._handle_catchall)
        return app

    @web.middleware
    async def _server_header_middleware(self, request: web.Request, handler):
        """Add realistic server headers to all responses."""
        response = await handler(request)
        response.headers["Server"] = HTTP_SERVER_HEADER
        response.headers["X-Powered-By"] = "PHP/8.1.2"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    async def _log_request(self, request: web.Request, response_body: str) -> None:
        """Log HTTP request details through the unified pipeline."""
        if not self._log_callback:
            return

        peername = request.remote
        port = request.transport.get_extra_info("peername")[1] if request.transport else 0

        # Build input string capturing method, path, headers, and body
        headers_str = json.dumps(dict(request.headers))
        body = ""
        try:
            body = await request.text()
        except Exception:
            pass

        input_received = (
            f"{request.method} {request.path_qs} HTTP/1.1 | "
            f"Headers: {headers_str}"
        )
        if body:
            input_received += f" | Body: {body}"

        # Create a temporary session for logging
        session = await session_manager.create_session(peername, port, "HTTP")
        try:
            # === PIPELINE: Session start with HTTP fingerprinting ===
            await command_pipeline.on_session_start(
                session, http_headers=dict(request.headers)
            )

            await self._log_callback(
                session=session,
                input_received=input_received,
                ai_response=response_body[:500],
            )
        finally:
            await command_pipeline.on_session_end(session)
            await session_manager.destroy_session(peername, port)

    async def _handle_root(self, request: web.Request) -> web.Response:
        """Serve the corporate login page at root."""
        await self._log_request(request, "(login page served)")
        return web.Response(
            text=CORPORATE_LOGIN_PAGE,
            content_type="text/html",
            status=200,
        )

    async def _handle_login(self, request: web.Request) -> web.Response:
        """Handle login form submissions and GET requests."""
        if request.method == "POST":
            # Parse form data
            try:
                data = await request.post()
                username = data.get("username", "")
                password = data.get("password", "")
            except Exception:
                username = password = "(parse error)"

            logger.info(
                f"[HTTP] Login attempt: {username}:{password} from {request.remote}"
            )

            # Log the credential capture
            input_str = f"POST /login | username={username}&password={password}"
            await self._log_request(request, f"Login captured: {username}:{password}")

            # Always show "invalid" to encourage more attempts
            page = CORPORATE_LOGIN_PAGE.replace(
                'display: none;', 'display: block;'
            )
            return web.Response(text=page, content_type="text/html", status=200)

        # GET /login - redirect to root
        await self._log_request(request, "(login page served)")
        return web.Response(
            text=CORPORATE_LOGIN_PAGE,
            content_type="text/html",
            status=200,
        )

    async def _handle_server_status(self, request: web.Request) -> web.Response:
        """Serve a realistic Apache server-status page."""
        await self._log_request(request, "(server-status page served)")
        return web.Response(
            text=SERVER_STATUS_PAGE,
            content_type="text/html",
            status=200,
        )

    async def _handle_admin(self, request: web.Request) -> web.Response:
        """Serve the fake admin panel with juicy-looking credentials."""
        await self._log_request(request, "(admin panel served)")
        return web.Response(
            text=ADMIN_PANEL_PAGE,
            content_type="text/html",
            status=200,
        )

    async def _handle_api(self, request: web.Request) -> web.Response:
        """Handle API endpoint probing."""
        path = request.match_info.get("path", "")

        # Simulate various API responses
        if "status" in path or "health" in path:
            response_data = {
                "status": "healthy",
                "version": "2.4.1",
                "uptime": 298521,
                "services": {
                    "database": "connected",
                    "cache": "connected",
                    "queue": "connected",
                },
            }
        elif "users" in path or "user" in path:
            response_data = {
                "error": "Unauthorized",
                "message": "Valid API key required",
                "hint": "Use X-API-Key header",
            }
        else:
            response_data = {
                "error": "Not Found",
                "endpoints": [
                    "/api/v2/status",
                    "/api/v2/users",
                    "/api/v2/upload",
                    "/api/v2/config",
                ],
            }

        body = json.dumps(response_data, indent=2)
        await self._log_request(request, body)
        return web.Response(
            text=body,
            content_type="application/json",
            status=200 if "status" in path else 401 if "users" in path else 404,
        )

    async def _handle_wordpress(self, request: web.Request) -> web.Response:
        """Handle WordPress admin/login probes (very common in the wild)."""
        await self._log_request(request, "(wordpress probe - login page served)")
        # Redirect to our corporate login to capture creds
        return web.Response(
            text=CORPORATE_LOGIN_PAGE,
            content_type="text/html",
            status=200,
        )

    async def _handle_env(self, request: web.Request) -> web.Response:
        """Serve a fake .env file to attract attackers looking for exposed configs."""
        env_content = (
            "APP_NAME=CorpNet\n"
            "APP_ENV=production\n"
            "APP_KEY=base64:rG3nL8mK9pQ2vX5wZ7yB0cF4hJ6lN8oR1tU3wY5zA=\n"
            "APP_DEBUG=false\n"
            "APP_URL=http://corp-srv-prod-01.internal\n"
            "\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=10.0.4.5\n"
            "DB_PORT=3306\n"
            "DB_DATABASE=corpnet_production\n"
            "DB_USERNAME=app_service\n"
            "DB_PASSWORD=Pr0d_S3cur3!_2024\n"
            "\n"
            "REDIS_HOST=10.0.4.11\n"
            "REDIS_PASSWORD=r3d1s_c@ch3\n"
            "REDIS_PORT=6379\n"
            "\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "AWS_DEFAULT_REGION=us-east-1\n"
            "AWS_BUCKET=corpnet-backups-prod\n"
        )
        await self._log_request(request, "(env file served)")
        logger.info(f"[HTTP] .env probe from {request.remote}")
        return web.Response(
            text=env_content,
            content_type="text/plain",
            status=200,
        )

    async def _handle_git_exposure(self, request: web.Request) -> web.Response:
        """Handle .git directory probes."""
        path = request.match_info.get("path", "")
        await self._log_request(request, f"(git probe: .git/{path})")
        logger.info(f"[HTTP] .git probe: /.git/{path} from {request.remote}")

        if path == "config" or path == "config/":
            git_config = (
                "[core]\n"
                "    repositoryformatversion = 0\n"
                "    filemode = true\n"
                "    bare = false\n"
                "[remote \"origin\"]\n"
                "    url = git@github.com:corpnet/internal-portal.git\n"
                "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
                "[branch \"main\"]\n"
                "    remote = origin\n"
                "    merge = refs/heads/main\n"
            )
            return web.Response(text=git_config, content_type="text/plain")

        if path == "HEAD":
            return web.Response(
                text="ref: refs/heads/main\n", content_type="text/plain"
            )

        return web.Response(text=FORBIDDEN_PAGE, content_type="text/html", status=403)

    async def _handle_robots(self, request: web.Request) -> web.Response:
        """Serve robots.txt with enticing disallowed paths."""
        robots = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /api/\n"
            "Disallow: /backup/\n"
            "Disallow: /config/\n"
            "Disallow: /internal/\n"
            "Disallow: /server-status\n"
            "Disallow: /.env\n"
        )
        await self._log_request(request, "(robots.txt served)")
        return web.Response(text=robots, content_type="text/plain", status=200)

    async def _handle_catchall(self, request: web.Request) -> web.Response:
        """Handle all other requests with a 404 page."""
        path = request.match_info.get("path", "")
        await self._log_request(request, f"(404 for /{path})")
        return web.Response(
            text=NOT_FOUND_PAGE,
            content_type="text/html",
            status=404,
        )


async def start_http_server(
    host: str = "0.0.0.0",
    port: int = HTTP_PORT,
    log_callback: Optional[Callable[..., Awaitable]] = None,
) -> web.AppRunner:
    """
    Start the HTTP honeypot server on a given port.

    Args:
        host: Bind address (default: all interfaces).
        port: Listen port.
        log_callback: Async callback for logging interactions.

    Returns:
        The aiohttp AppRunner for lifecycle management.
    """
    handler = HTTPHoneypotHandler(log_callback)
    app = handler.create_app()
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info(f"[HTTP] Honeypot listening on {host}:{port}")
    return runner


async def start_http_servers(
    host: str = "0.0.0.0",
    log_callback: Optional[Callable[..., Awaitable]] = None,
) -> list:
    """
    Start HTTP honeypot on both port 80 and 8080.

    Returns:
        List of AppRunner instances for lifecycle management.
    """
    runners = []
    for port in [HTTP_PORT, HTTP_ALT_PORT]:
        try:
            runner = await start_http_server(host, port, log_callback)
            runners.append(runner)
        except OSError as e:
            logger.error(f"[HTTP] Failed to bind port {port}: {e}")
    return runners
