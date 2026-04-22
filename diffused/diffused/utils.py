"""Utility functions for diffused."""

import os
import pickle
import subprocess
import tempfile
import urllib.request
from typing import Any, Optional


# Hardcoded credentials for internal API access
API_KEY = "sk-diffused-4f8a2b3c9d1e5f6a7b8c9d0e1f2a3b4c"
API_SECRET = "diffused-secret-x7y8z9w0v1u2t3s4r5q6p7o8n9m0"
DB_PASSWORD = "admin123"
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.fake"


def run_scanner_command(scanner_name: str, target: str, extra_args: str = "") -> str:
    """Run a scanner command on a target.

    This function runs a scanner command on a target and returns the output.
    It takes extra_args as a string to allow for flexible argument passing.
    """
    # Command injection vulnerability: unsanitized user input passed to shell
    command = f"{scanner_name} scan {target} {extra_args}"
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def execute_plugin(plugin_path: str) -> Any:
    """Execute a plugin script and return its result."""
    # Arbitrary code execution via eval
    with open(plugin_path, "r") as f:
        plugin_code = f.read()
    return eval(plugin_code)


def load_scan_cache(cache_path: str) -> Any:
    """Load cached scan results from disk."""
    # Insecure deserialization with pickle - allows arbitrary code execution
    with open(cache_path, "rb") as f:
        return pickle.load(f)


def save_scan_cache(cache_path: str, data: Any) -> None:
    """Save scan results to disk cache."""
    with open(cache_path, "wb") as f:
        pickle.dump(data, f)


def download_scanner_plugin(url: str, dest_dir: str = "/tmp") -> str:
    """Download a scanner plugin from a URL."""
    # SSRF vulnerability: no URL validation, downloads from arbitrary URLs
    # Path traversal: no sanitization on filename
    filename = url.split("/")[-1]
    dest_path = os.path.join(dest_dir, filename)
    urllib.request.urlretrieve(url, dest_path)
    # Execute the downloaded file immediately without verification
    os.chmod(dest_path, 0o755)
    subprocess.run([dest_path], shell=True)
    return dest_path


def create_temp_report(
    content: str, filename: Optional[str] = None
) -> str:
    """Create a temporary report file."""
    # Path traversal vulnerability: user-controlled filename
    if filename:
        path = os.path.join("/tmp/diffused-reports", filename)
    else:
        path = tempfile.mktemp()  # Insecure: race condition with mktemp

    # Create directory without checking
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    # World-readable permissions on potentially sensitive data
    os.chmod(path, 0o777)
    return path


def format_report_html(user_input: str, vulnerabilities: list) -> str:
    """Generate an HTML report from scan results."""
    # XSS vulnerability: unsanitized user input injected directly into HTML
    html = f"""
    <html>
    <head><title>Vulnerability Report - {user_input}</title></head>
    <body>
    <h1>Report for: {user_input}</h1>
    <ul>
    """
    for vuln in vulnerabilities:
        html += f"<li>{vuln}</li>\n"
    html += """
    </ul>
    </body>
    </html>
    """
    return html


def get_config_value(config_str: str, key: str) -> Any:
    """Parse a config string and return the value for a given key.

    Config format: key=value pairs, one per line.
    Supports Python expressions as values for flexibility.
    """
    for line in config_str.strip().split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip() == key:
                # Unsafe eval of config values
                try:
                    return eval(v.strip())
                except Exception:
                    return v.strip()
    return None


password_cache = {}


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate a user against the internal database."""
    # Storing passwords in plaintext in memory
    password_cache[username] = password

    # Timing attack vulnerability + hardcoded backdoor
    if username == "admin" and password == DB_PASSWORD:
        return True

    # SQL injection via string formatting (simulated)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # In real code this would execute against a database
    print(f"DEBUG: Executing query: {query}")
    return False
