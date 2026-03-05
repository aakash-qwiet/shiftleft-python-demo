"""
Test vulnerability patterns for security scanner validation.
These are intentional vulnerabilities for testing purposes.
"""

import os
import subprocess
import pickle
import hashlib
import tempfile
import requests
from flask import Blueprint, request, render_template_string

bp = Blueprint("test_vulns", __name__, url_prefix="/test")

# =============================================================================
# 1. HARDCODED CREDENTIALS (should be detected)
# =============================================================================
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----"""


# =============================================================================
# 2. SQL INJECTION (should be detected)
# =============================================================================
@bp.route("/sqli")
def sql_injection_test():
    user_input = request.args.get("id", "")
    # Vulnerable: string concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_input
    return query


@bp.route("/sqli2")
def sql_injection_format():
    user_input = request.args.get("name", "")
    # Vulnerable: f-string in SQL query
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query


# =============================================================================
# 3. COMMAND INJECTION (should be detected)
# =============================================================================
@bp.route("/cmdi")
def command_injection_test():
    filename = request.args.get("file", "")
    # Vulnerable: user input in shell command
    result = os.system("cat " + filename)
    return str(result)


@bp.route("/cmdi2")
def command_injection_subprocess():
    cmd = request.args.get("cmd", "ls")
    # Vulnerable: shell=True with user input
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


# =============================================================================
# 4. XSS - CROSS-SITE SCRIPTING (should be detected)
# =============================================================================
@bp.route("/xss")
def xss_reflected():
    name = request.args.get("name", "")
    # Vulnerable: user input directly in HTML response
    return f"<html><body>Hello {name}</body></html>"


@bp.route("/xss2")
def xss_template():
    user_input = request.args.get("content", "")
    # Vulnerable: render_template_string with user input
    template = f"<div>{user_input}</div>"
    return render_template_string(template)


# =============================================================================
# 5. PATH TRAVERSAL (should be detected)
# =============================================================================
@bp.route("/path")
def path_traversal_test():
    filename = request.args.get("file", "default.txt")
    # Vulnerable: no validation of path
    filepath = "/var/www/files/" + filename
    with open(filepath, "r") as f:
        return f.read()


@bp.route("/path2")
def path_traversal_join():
    filename = request.args.get("file", "")
    # Vulnerable: os.path.join doesn't prevent traversal with absolute paths
    filepath = os.path.join("/uploads", filename)
    return open(filepath).read()


# =============================================================================
# 6. INSECURE DESERIALIZATION (should be detected)
# =============================================================================
@bp.route("/pickle", methods=["POST"])
def insecure_pickle():
    data = request.get_data()
    # Vulnerable: unpickling untrusted data
    obj = pickle.loads(data)
    return str(obj)


# =============================================================================
# 7. WEAK CRYPTOGRAPHY (should be detected)
# =============================================================================
@bp.route("/hash")
def weak_hash():
    password = request.args.get("password", "")
    # Vulnerable: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


@bp.route("/hash2")
def weak_hash_sha1():
    data = request.args.get("data", "")
    # Vulnerable: SHA1 is deprecated for security purposes
    hashed = hashlib.sha1(data.encode()).hexdigest()
    return hashed


# =============================================================================
# 8. SSRF - SERVER-SIDE REQUEST FORGERY (should be detected)
# =============================================================================
@bp.route("/fetch")
def ssrf_test():
    url = request.args.get("url", "")
    # Vulnerable: fetching arbitrary URLs
    response = requests.get(url)
    return response.text


# =============================================================================
# 9. OPEN REDIRECT (should be detected)
# =============================================================================
@bp.route("/redirect")
def open_redirect():
    from flask import redirect
    target = request.args.get("url", "/")
    # Vulnerable: redirecting to user-supplied URL
    return redirect(target)


# =============================================================================
# 10. INSECURE TEMP FILE (should be detected)
# =============================================================================
@bp.route("/temp")
def insecure_tempfile():
    # Vulnerable: predictable temp file name
    tmp_path = "/tmp/myapp_" + request.args.get("id", "default")
    with open(tmp_path, "w") as f:
        f.write(request.args.get("data", ""))
    return "Written"


# =============================================================================
# 11. HARDCODED IP / DEBUG MODE (should be detected)
# =============================================================================
DEBUG_MODE = True
BIND_ADDRESS = "0.0.0.0"
ADMIN_EMAIL = "admin@example.com"


# =============================================================================
# 12. EVAL/EXEC (should be detected)
# =============================================================================
@bp.route("/eval")
def dangerous_eval():
    expr = request.args.get("expr", "1+1")
    # Vulnerable: eval with user input
    result = eval(expr)
    return str(result)


@bp.route("/exec")
def dangerous_exec():
    code = request.args.get("code", "")
    # Vulnerable: exec with user input
    exec(code)
    return "Executed"
