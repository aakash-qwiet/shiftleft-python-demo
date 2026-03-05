"""
False positive candidate patterns for security scanner validation.
These patterns MAY trigger scanner warnings but are actually SAFE.
Used to test scanner's ability to distinguish true vs false positives.
"""

import os
import subprocess
import pickle
import hashlib
import hmac
import re
import urllib.parse
from flask import Blueprint, request, redirect, escape

bp = Blueprint("fp_candidates", __name__, url_prefix="/fp")

# =============================================================================
# 1. PARAMETERIZED SQL (looks like SQLi but is SAFE)
# =============================================================================
@bp.route("/safe_sql")
def safe_sql_parameterized():
    user_id = request.args.get("id", "")
    # SAFE: Using parameterized query - not vulnerable
    query = "SELECT * FROM users WHERE id = ?"
    # The actual execution would use: cursor.execute(query, (user_id,))
    return f"Would execute: {query} with param: {user_id}"


@bp.route("/safe_sql2")
def safe_sql_with_int_cast():
    user_id = request.args.get("id", "0")
    # SAFE: Casting to int prevents injection
    safe_id = int(user_id)
    query = f"SELECT * FROM users WHERE id = {safe_id}"
    return query


# =============================================================================
# 2. HARDCODED VALUES THAT ARE NOT SECRETS
# =============================================================================
# SAFE: These are not real credentials - they're defaults/placeholders/examples
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
EXAMPLE_API_KEY = "your-api-key-here"  # Placeholder, not real
DOCUMENTATION_PASSWORD = "password123"  # Example for docs only
TEST_MODE = True  # Not a secret

# SAFE: Public keys are meant to be public
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3
-----END PUBLIC KEY-----"""

# SAFE: Hash of a password, not the password itself
PASSWORD_HASH = "5f4dcc3b5aa765d61d8327deb882cf99"


# =============================================================================
# 3. COMMAND EXECUTION WITH HARDCODED/VALIDATED INPUT
# =============================================================================
@bp.route("/safe_cmd")
def safe_command_hardcoded():
    # SAFE: No user input in command
    result = subprocess.run(["ls", "-la", "/var/log"], capture_output=True)
    return result.stdout


@bp.route("/safe_cmd2")
def safe_command_allowlist():
    action = request.args.get("action", "status")
    # SAFE: Allowlist validation
    allowed_actions = {"status": "systemctl status nginx",
                       "version": "nginx -v"}
    if action not in allowed_actions:
        return "Invalid action", 400
    # Only executes pre-defined commands
    cmd = allowed_actions[action]
    return f"Would run: {cmd}"


@bp.route("/safe_cmd3")
def safe_command_no_shell():
    filename = request.args.get("file", "")
    # SAFE: shell=False and using list (no shell injection possible)
    # Also validating the filename
    if not re.match(r'^[a-zA-Z0-9_\-]+\.txt$', filename):
        return "Invalid filename", 400
    result = subprocess.run(["cat", filename], capture_output=True, shell=False)
    return result.stdout


# =============================================================================
# 4. XSS WITH PROPER ESCAPING
# =============================================================================
@bp.route("/safe_xss")
def safe_xss_escaped():
    name = request.args.get("name", "")
    # SAFE: Using Flask's escape function
    safe_name = escape(name)
    return f"<html><body>Hello {safe_name}</body></html>"


@bp.route("/safe_xss2")
def safe_xss_text_only():
    data = request.args.get("data", "")
    # SAFE: Returning as plain text, not HTML
    return data, 200, {'Content-Type': 'text/plain'}


# =============================================================================
# 5. PATH OPERATIONS WITH VALIDATION
# =============================================================================
@bp.route("/safe_path")
def safe_path_validated():
    filename = request.args.get("file", "default.txt")
    # SAFE: Validating filename format
    if not re.match(r'^[a-zA-Z0-9_\-]+\.(txt|pdf|jpg)$', filename):
        return "Invalid filename", 400
    if ".." in filename or filename.startswith("/"):
        return "Invalid path", 400
    filepath = os.path.join("/var/www/files/", filename)
    return f"Would read: {filepath}"


@bp.route("/safe_path2")
def safe_path_realpath():
    filename = request.args.get("file", "")
    base_dir = "/var/www/uploads"
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    # SAFE: Checking resolved path is within allowed directory
    if not filepath.startswith(base_dir):
        return "Access denied", 403
    return f"Would read: {filepath}"


# =============================================================================
# 6. PICKLE WITH TRUSTED DATA
# =============================================================================
@bp.route("/safe_pickle")
def safe_pickle_internal():
    # SAFE: Pickling internal data, not user input
    internal_data = {"count": 42, "items": ["a", "b", "c"]}
    serialized = pickle.dumps(internal_data)
    # Loading our own serialized data
    restored = pickle.loads(serialized)
    return str(restored)


# =============================================================================
# 7. HASH FUNCTIONS FOR NON-SECURITY PURPOSES
# =============================================================================
@bp.route("/safe_hash")
def safe_hash_checksum():
    data = request.args.get("data", "")
    # SAFE: MD5 used for checksum/cache key, not security
    cache_key = hashlib.md5(data.encode()).hexdigest()
    return f"Cache key: {cache_key}"


@bp.route("/safe_hash2")
def safe_hash_etag():
    content = "static content here"
    # SAFE: SHA1 for ETag generation, not password hashing
    etag = hashlib.sha1(content.encode()).hexdigest()
    return content, 200, {'ETag': etag}


@bp.route("/safe_password_hash")
def safe_password_proper():
    password = request.args.get("password", "")
    # SAFE: Using HMAC with a key (better than plain hash)
    secret_key = os.environ.get("SECRET_KEY", "").encode()
    hashed = hmac.new(secret_key, password.encode(), hashlib.sha256).hexdigest()
    return f"Hashed: {hashed}"


# =============================================================================
# 8. URL REDIRECT WITH VALIDATION
# =============================================================================
@bp.route("/safe_redirect")
def safe_redirect_validated():
    target = request.args.get("url", "/")
    # SAFE: Only allowing relative URLs
    if target.startswith("/") and not target.startswith("//"):
        return redirect(target)
    return "Invalid redirect", 400


@bp.route("/safe_redirect2")
def safe_redirect_allowlist():
    target = request.args.get("url", "")
    # SAFE: Allowlist of domains
    allowed_domains = ["example.com", "trusted.org"]
    parsed = urllib.parse.urlparse(target)
    if parsed.netloc and parsed.netloc not in allowed_domains:
        return "Redirect not allowed", 400
    return redirect(target)


# =============================================================================
# 9. REQUESTS WITH VALIDATED URLS
# =============================================================================
@bp.route("/safe_fetch")
def safe_fetch_validated():
    import requests
    url = request.args.get("url", "")
    # SAFE: Allowlist validation
    allowed_hosts = ["api.github.com", "api.example.com"]
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc not in allowed_hosts:
        return "Host not allowed", 400
    # Only fetches from allowed hosts
    return f"Would fetch: {url}"


# =============================================================================
# 10. EVAL-LIKE WITH SAFE ALTERNATIVES
# =============================================================================
@bp.route("/safe_calc")
def safe_calculation():
    expr = request.args.get("expr", "1+1")
    # SAFE: Only allowing digits and basic math operators
    if not re.match(r'^[\d\+\-\*\/\.\(\)\s]+$', expr):
        return "Invalid expression", 400
    # Still risky but much safer than raw eval
    # In production, use ast.literal_eval or a proper math parser
    return f"Expression: {expr}"


@bp.route("/safe_json")
def safe_json_parse():
    import json
    data = request.args.get("data", "{}")
    # SAFE: json.loads is safe, unlike eval/pickle
    try:
        parsed = json.loads(data)
        return str(parsed)
    except json.JSONDecodeError:
        return "Invalid JSON", 400


# =============================================================================
# 11. LOGGING THAT LOOKS SUSPICIOUS
# =============================================================================
@bp.route("/safe_log")
def safe_logging():
    import logging
    user_action = request.args.get("action", "")
    # SAFE: Logging user input is fine (not executing it)
    # Scanner might flag "user input flows to..." but it's just a log
    logging.info(f"User performed action: {user_action}")
    return "Logged"


# =============================================================================
# 12. ENVIRONMENT VARIABLE PATTERNS
# =============================================================================
@bp.route("/safe_env")
def safe_env_access():
    # SAFE: Reading env vars is fine, it's hardcoding secrets that's bad
    db_host = os.environ.get("DB_HOST", "localhost")
    api_key = os.environ.get("API_KEY", "")
    return f"DB Host: {db_host}"
