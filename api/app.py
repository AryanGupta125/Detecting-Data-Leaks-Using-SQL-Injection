"""
Flask Web API — SQL Injection Detection & Security System
Database: AWS RDS MySQL
Local run: python app.py
Vercel entry point: api/app.py
"""

import os
from flask import Flask, request, jsonify, send_from_directory

# Project root is one level above /api
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

app = Flask(
    __name__,
    static_folder=PUBLIC_DIR,
    static_url_path=""
)

# --------------------------------------------------
# Lazy import database functions
# --------------------------------------------------

def get_db_functions():
    from security_system import (
        init_db,
        secure_register,
        secure_login,
        test_injection,
        get_users,
        get_security_logs,
        get_attacks,
        get_stats
    )

    return (
        init_db,
        secure_register,
        secure_login,
        test_injection,
        get_users,
        get_security_logs,
        get_attacks,
        get_stats
    )


# --------------------------------------------------
# Database initialization
# --------------------------------------------------

_db_initialized = False


def ensure_db_initialized():
    """
    Initialize the RDS database only when the first database
    request arrives. This avoids database work during Vercel
    function import/startup.
    """
    global _db_initialized

    if _db_initialized:
        return

    try:
        init_db, _, _, _, _, _, _, _ = get_db_functions()
        init_db()
        _db_initialized = True
        print("[DB] AWS RDS tables initialized successfully.")

    except Exception as e:
        # Do not prevent Flask/Vercel from importing the app.
        # The individual API request will return the real error.
        print(f"[DB INIT ERROR] {type(e).__name__}: {e}")
        _db_initialized = False


# --------------------------------------------------
# Home page
# --------------------------------------------------

@app.route("/")
def index():
    index_file = os.path.join(PUBLIC_DIR, "index.html")

    if not os.path.exists(index_file):
        return jsonify({
            "error": "index.html not found",
            "expected_path": index_file
        }), 500

    return send_from_directory(PUBLIC_DIR, "index.html")


# --------------------------------------------------
# Register
# --------------------------------------------------

@app.route("/api/register", methods=["POST"])
def api_register():
    ensure_db_initialized()

    try:
        _, secure_register, _, _, _, _, _, _ = get_db_functions()

        data = request.get_json(silent=True) or {}

        username = str(data.get("username", "")).strip()
        email = str(data.get("email", "")).strip()
        password = str(data.get("password", ""))

        if not username or not email or not password:
            return jsonify({
                "success": False,
                "status": "ERROR",
                "message": "Username, email and password are required."
            }), 400

        ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr or "unknown"
        ).split(",")[0].strip()

        result = secure_register(username, email, password, ip)
        return jsonify(result)

    except Exception as e:
        print(f"[API REGISTER ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "success": False,
            "status": "ERROR",
            "message": "Database operation failed.",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    ensure_db_initialized()

    try:
        _, _, secure_login, _, _, _, _, _ = get_db_functions()

        data = request.get_json(silent=True) or {}

        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not username or not password:
            return jsonify({
                "success": False,
                "status": "ERROR",
                "message": "Username and password are required."
            }), 400

        ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr or "unknown"
        ).split(",")[0].strip()

        result = secure_login(username, password, ip)
        return jsonify(result)

    except Exception as e:
        print(f"[API LOGIN ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "success": False,
            "status": "ERROR",
            "message": "Database operation failed.",
            "details": str(e)
        }), 500


# --------------------------------------------------
# SQL Injection test
# --------------------------------------------------

@app.route("/api/test-injection", methods=["POST"])
def api_test_injection():
    ensure_db_initialized()

    try:
        _, _, _, test_injection, _, _, _, _ = get_db_functions()

        data = request.get_json(silent=True) or {}
        test_input = str(data.get("input", ""))

        ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr or "unknown"
        ).split(",")[0].strip()

        result = test_injection(test_input, ip)
        return jsonify(result)

    except Exception as e:
        print(f"[API INJECTION TEST ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "success": False,
            "status": "ERROR",
            "message": "Database operation failed.",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Get users
# --------------------------------------------------

@app.route("/api/users", methods=["GET"])
def api_users():
    ensure_db_initialized()

    try:
        _, _, _, _, get_users, _, _, _ = get_db_functions()
        return jsonify(get_users())

    except Exception as e:
        print(f"[API USERS ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "error": "Could not retrieve users",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Get security logs
# --------------------------------------------------

@app.route("/api/logs", methods=["GET"])
def api_logs():
    ensure_db_initialized()

    try:
        _, _, _, _, _, get_security_logs, _, _ = get_db_functions()
        return jsonify(get_security_logs())

    except Exception as e:
        print(f"[API LOGS ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "error": "Could not retrieve security logs",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Get detected attacks
# --------------------------------------------------

@app.route("/api/attacks", methods=["GET"])
def api_attacks():
    ensure_db_initialized()

    try:
        _, _, _, _, _, _, get_attacks, _ = get_db_functions()
        return jsonify(get_attacks())

    except Exception as e:
        print(f"[API ATTACKS ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "error": "Could not retrieve detected attacks",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Get statistics
# --------------------------------------------------

@app.route("/api/stats", methods=["GET"])
def api_stats():
    ensure_db_initialized()

    try:
        _, _, _, _, _, _, _, get_stats = get_db_functions()
        return jsonify(get_stats())

    except Exception as e:
        print(f"[API STATS ERROR] {type(e).__name__}: {e}")

        return jsonify({
            "error": "Could not retrieve statistics",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Local development
# --------------------------------------------------

if __name__ == "__main__":
    print("Starting SQL Injection Detection & Security System...")

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )
