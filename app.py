"""
Flask Web API — SQL Injection Detection & Security System
Database: AWS RDS MySQL
"""

import os
from flask import Flask, request, jsonify


app = Flask(__name__)


# ============================================================
# LAZY DATABASE IMPORT
# ============================================================

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


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

_db_initialized = False


def ensure_db_initialized():

    global _db_initialized

    if _db_initialized:
        return

    try:

        init_db, _, _, _, _, _, _, _ = get_db_functions()

        init_db()

        _db_initialized = True

        print("[DB] Security database initialized successfully.")

    except Exception as e:

        print(
            f"[DB INIT ERROR] "
            f"{type(e).__name__}: {e}"
        )


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def index():

    public_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "public"
    )

    index_file = os.path.join(
        public_dir,
        "index.html"
    )

    if not os.path.exists(index_file):

        return jsonify({
            "error": "index.html not found",
            "expected_path": index_file
        }), 500

    with open(
        index_file,
        "r",
        encoding="utf-8"
    ) as file:

        return file.read()


# ============================================================
# REGISTER
# ============================================================

@app.route("/api/register", methods=["POST"])
def api_register():

    ensure_db_initialized()

    try:

        (
            _,
            secure_register,
            _,
            _,
            _,
            _,
            _,
            _
        ) = get_db_functions()

        data = request.get_json(silent=True) or {}

        ip = request.remote_addr

        result = secure_register(
            data.get("username", ""),
            data.get("email", ""),
            data.get("password", ""),
            ip
        )

        return jsonify(result)

    except Exception as e:

        print(
            f"[REGISTER ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Registration failed",
            "details": str(e)
        }), 500


# ============================================================
# LOGIN
# ============================================================

@app.route("/api/login", methods=["POST"])
def api_login():

    ensure_db_initialized()

    try:

        (
            _,
            _,
            secure_login,
            _,
            _,
            _,
            _,
            _
        ) = get_db_functions()

        data = request.get_json(silent=True) or {}

        ip = request.remote_addr

        result = secure_login(
            data.get("username", ""),
            data.get("password", ""),
            ip
        )

        return jsonify(result)

    except Exception as e:

        print(
            f"[LOGIN ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Login failed",
            "details": str(e)
        }), 500


# ============================================================
# SQL INJECTION TEST
# ============================================================

@app.route("/api/test-injection", methods=["POST"])
def api_test_injection():

    ensure_db_initialized()

    try:

        (
            _,
            _,
            _,
            test_injection,
            _,
            _,
            _,
            _
        ) = get_db_functions()

        data = request.get_json(
            silent=True
        ) or {}

        ip = request.remote_addr

        result = test_injection(
            data.get("input", ""),
            ip
        )

        return jsonify(result)

    except Exception as e:

        print(
            f"[INJECTION TEST ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Injection test failed",
            "details": str(e)
        }), 500


# ============================================================
# USERS
# ============================================================

@app.route("/api/users", methods=["GET"])
def api_users():

    ensure_db_initialized()

    try:

        (
            _,
            _,
            _,
            _,
            get_users,
            _,
            _,
            _
        ) = get_db_functions()

        return jsonify(
            get_users()
        )

    except Exception as e:

        print(
            f"[USERS ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Could not retrieve users",
            "details": str(e)
        }), 500


# ============================================================
# SECURITY LOGS
# ============================================================

@app.route("/api/logs", methods=["GET"])
def api_logs():

    ensure_db_initialized()

    try:

        (
            _,
            _,
            _,
            _,
            _,
            get_security_logs,
            _,
            _
        ) = get_db_functions()

        return jsonify(
            get_security_logs()
        )

    except Exception as e:

        print(
            f"[LOGS ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Could not retrieve security logs",
            "details": str(e)
        }), 500


# ============================================================
# ATTACKS
# ============================================================

@app.route("/api/attacks", methods=["GET"])
def api_attacks():

    ensure_db_initialized()

    try:

        (
            _,
            _,
            _,
            _,
            _,
            _,
            get_attacks,
            _
        ) = get_db_functions()

        return jsonify(
            get_attacks()
        )

    except Exception as e:

        print(
            f"[ATTACKS ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Could not retrieve attacks",
            "details": str(e)
        }), 500


# ============================================================
# STATISTICS
# ============================================================

@app.route("/api/stats", methods=["GET"])
def api_stats():

    ensure_db_initialized()

    try:

        (
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            get_stats
        ) = get_db_functions()

        return jsonify(
            get_stats()
        )

    except Exception as e:

        print(
            f"[STATS ERROR] "
            f"{type(e).__name__}: {e}"
        )

        return jsonify({
            "error": "Could not retrieve statistics",
            "details": str(e)
        }), 500


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    print(
        "Starting SQL Injection "
        "Detection & Security System..."
    )

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )