"""
Task 2: Detecting Data Leaks Using SQL Injection
Security System — Core Logic
Database: AWS RDS MySQL
"""

import os
import re
import hashlib
import base64
import mysql.connector
from mysql.connector import Error
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ============================================================
# AES-256 ENCRYPTION
# ============================================================

def get_aes_key() -> bytes:
    """
    Get AES-256 key from environment.
    AES requires exactly 32 bytes.
    """

    key = os.environ.get(
        "AES_SECRET_KEY",
        "ThisIsA32ByteSecretKey!!SECURE!!"
    )

    # Ensure exactly 32 bytes
    key_bytes = key.encode("utf-8")

    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b"0")

    return key_bytes[:32]


def encrypt_data(plaintext: str) -> str:
    """
    Encrypt sensitive data using AES-256-GCM.

    Stored format:
    nonce + authentication tag + ciphertext
    """

    key = get_aes_key()

    nonce = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = (
        encryptor.update(
            plaintext.encode("utf-8")
        )
        + encryptor.finalize()
    )

    encrypted = base64.b64encode(
        nonce + encryptor.tag + ciphertext
    ).decode("utf-8")

    return encrypted


def decrypt_data(encrypted: str) -> str:
    """
    Decrypt AES-256-GCM encrypted data.
    """

    try:

        key = get_aes_key()

        raw = base64.b64decode(
            encrypted.encode("utf-8")
        )

        nonce = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()

        plaintext = (
            decryptor.update(ciphertext)
            + decryptor.finalize()
        )

        return plaintext.decode("utf-8")

    except Exception:
        return "[DECRYPTION FAILED]"


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str) -> str:
    """
    Hash password using SHA-256 + salt.
    """

    salt = os.environ.get(
        "PASSWORD_SALT",
        "SECURE_SALT_2024"
    )

    return hashlib.sha256(
        f"{salt}{password}".encode("utf-8")
    ).hexdigest()


# ============================================================
# SQL INJECTION DETECTION
# ============================================================

SQL_INJECTION_PATTERNS = [

    r"(\bOR\b|\bAND\b)\s+[\w'\"]+\s*=\s*[\w'\"]+",

    r"--\s",

    r"/\*.*?\*/",

    r";.*?(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)",

    r"\bDROP\b",

    r"\bDELETE\b\s+\bFROM\b",

    r"\bINSERT\b\s+\bINTO\b",

    r"\bUNION\b\s+\bSELECT\b",

    r"\bEXEC\b|\bEXECUTE\b",

    r"\bxp_\w+",

    r"'\s*;\s*",

    r"\bSLEEP\b\s*\(",

    r"\bWAITFOR\b",

    r"\bBENCHMARK\b\s*\(",

    r"0x[0-9a-fA-F]+",

    r"\bCHAR\b\s*\(",

    r"\bCONCAT\b\s*\(",

    r"\bINFORMATION_SCHEMA\b",

    r"\bSYSOBJECTS\b|\bSYSCOLUMNS\b",

    r"'\s*OR\s*'",

    r'"\s*OR\s*"'
]


def detect_sql_injection(user_input: str) -> dict:
    """
    Detect possible SQL injection patterns.
    """

    if not user_input:

        return {
            "is_malicious": False,
            "pattern_matched": None,
            "risk_level": "NONE"
        }

    input_upper = user_input.upper()

    for pattern in SQL_INJECTION_PATTERNS:

        if re.search(
            pattern,
            input_upper,
            re.IGNORECASE
        ):

            return {
                "is_malicious": True,
                "pattern_matched": pattern,
                "risk_level": "HIGH",
                "detail": (
                    f"SQL injection pattern detected: "
                    f"{pattern}"
                )
            }

    suspicious_chars = [
        "'",
        '"',
        ";",
        "--",
        "/*",
        "*/",
        "\\x",
        "%27",
        "%22"
    ]

    for char in suspicious_chars:

        if char in user_input:

            return {
                "is_malicious": True,
                "pattern_matched": char,
                "risk_level": "MEDIUM",
                "detail": (
                    f"Suspicious character detected: "
                    f"{char}"
                )
            }

    return {
        "is_malicious": False,
        "pattern_matched": None,
        "risk_level": "NONE"
    }


def sanitize_input(user_input: str) -> str:
    """
    Secondary input sanitization.
    """

    if not user_input:
        return ""

    sanitized = user_input.replace(
        "\x00",
        ""
    )

    sanitized = sanitized.replace(
        "'",
        "''"
    )

    return sanitized.strip()


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Connect to AWS RDS MySQL using environment variables.

    IMPORTANT:
    There is NO _get_mysql() function here.
    We directly use mysql.connector.
    """

    try:

        host = os.environ.get("DB_HOST")
        port = int(
            os.environ.get(
                "DB_PORT",
                "3306"
            )
        )
        user = os.environ.get("DB_USER")
        password = os.environ.get("DB_PASSWORD")
        database = os.environ.get("DB_NAME")

        if not host:
            raise ValueError(
                "DB_HOST environment variable is missing."
            )

        if not user:
            raise ValueError(
                "DB_USER environment variable is missing."
            )

        if not password:
            raise ValueError(
                "DB_PASSWORD environment variable is missing."
            )

        if not database:
            raise ValueError(
                "DB_NAME environment variable is missing."
            )

        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            connection_timeout=10
        )

        return conn

    except Error as e:

        print(
            f"[DB ERROR] "
            f"Could not connect to AWS RDS: {e}"
        )

        raise


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """
    Create database and required tables.
    """

    db_name = os.environ.get(
        "DB_NAME",
        "security_db"
    )

    # --------------------------------------------------------
    # Step 1: Create database
    # --------------------------------------------------------

    temp_conn = None
    temp_cursor = None

    try:

        temp_conn = mysql.connector.connect(
            host=os.environ.get("DB_HOST"),
            port=int(
                os.environ.get(
                    "DB_PORT",
                    "3306"
                )
            ),
            user=os.environ.get("DB_USER"),
            password=os.environ.get("DB_PASSWORD"),
            connection_timeout=10
        )

        temp_cursor = temp_conn.cursor()

        # DB_NAME comes from your environment variables.
        # It should be a trusted value.
        safe_db_name = db_name.replace("`", "")

        temp_cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{safe_db_name}`"
        )

        temp_conn.commit()

        print(
            f"[DB] Database '{safe_db_name}' ready."
        )

    except Error as e:

        print(
            f"[DB ERROR] "
            f"Could not create database: {e}"
        )

        raise

    finally:

        if temp_cursor:
            temp_cursor.close()

        if temp_conn:
            temp_conn.close()

    # --------------------------------------------------------
    # Step 2: Create tables
    # --------------------------------------------------------

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        # USERS TABLE
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                encrypted_email TEXT NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                created_at DATETIME NOT NULL
            )
        """)

        # SECURITY LOG TABLE
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                input_data TEXT NOT NULL,
                action VARCHAR(50) NOT NULL,
                risk_level VARCHAR(10) NOT NULL,
                is_malicious BOOLEAN NOT NULL,
                pattern_matched TEXT,
                ip_address VARCHAR(45),
                attempted_at DATETIME NOT NULL
            )
        """)

        # DETECTED ATTACKS TABLE
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detected_attacks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                attack_input TEXT NOT NULL,
                pattern_matched TEXT NOT NULL,
                risk_level VARCHAR(10) NOT NULL,
                blocked_at DATETIME NOT NULL
            )
        """)

        conn.commit()

        print(
            "[DB] All tables initialized successfully."
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# USER REGISTRATION
# ============================================================

def secure_register(
    username: str,
    email: str,
    password: str,
    ip: str = "unknown"
) -> dict:

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # SQL Injection Detection
    # --------------------------------------------------------

    for field_name, field_value in [
        ("username", username),
        ("email", email),
        ("password", password)
    ]:

        detection = detect_sql_injection(
            field_value
        )

        log_attempt(
            field_value,
            "REGISTER",
            detection,
            ip
        )

        if detection["is_malicious"]:

            log_attack(
                field_value,
                detection
            )

            return {
                "success": False,
                "status": "BLOCKED",
                "risk_level": detection["risk_level"],
                "message": (
                    f"SQL injection detected "
                    f"in {field_name} field. "
                    f"Access denied."
                ),
                "layer": (
                    "Layer 2 — SQL Injection Shield"
                )
            }

    # --------------------------------------------------------
    # Encryption + Hashing
    # --------------------------------------------------------

    encrypted_email = encrypt_data(
        email
    )

    password_hash = hash_password(
        password
    )

    clean_username = sanitize_input(
        username
    )

    # --------------------------------------------------------
    # Insert User
    # --------------------------------------------------------

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                encrypted_email,
                password_hash,
                created_at
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                clean_username,
                encrypted_email,
                password_hash,
                timestamp
            )
        )

        conn.commit()

        return {
            "success": True,
            "status": "REGISTERED",
            "message": (
                f"User '{username}' "
                f"registered securely."
            ),
            "security": (
                "AES-256 encrypted · "
                "SQL injection safe · "
                "Parameterized query"
            ),
            "layer": "Both layers passed ✓"
        }

    except Error as e:

        if "Duplicate entry" in str(e):

            return {
                "success": False,
                "status": "ERROR",
                "message": (
                    "Username already exists."
                )
            }

        return {
            "success": False,
            "status": "ERROR",
            "message": str(e)
        }

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# USER LOGIN
# ============================================================

def secure_login(
    username: str,
    password: str,
    ip: str = "unknown"
) -> dict:

    # --------------------------------------------------------
    # SQL Injection Detection
    # --------------------------------------------------------

    for field_name, field_value in [
        ("username", username),
        ("password", password)
    ]:

        detection = detect_sql_injection(
            field_value
        )

        log_attempt(
            field_value,
            "LOGIN",
            detection,
            ip
        )

        if detection["is_malicious"]:

            log_attack(
                field_value,
                detection
            )

            return {
                "success": False,
                "status": "BLOCKED",
                "risk_level": detection["risk_level"],
                "message": (
                    f"SQL injection detected "
                    f"in {field_name}. "
                    f"Access denied."
                ),
                "layer": (
                    "Layer 2 — SQL Injection Shield"
                )
            }

    # --------------------------------------------------------
    # Verify credentials
    # --------------------------------------------------------

    password_hash = hash_password(
        password
    )

    clean_username = sanitize_input(
        username
    )

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username
            FROM users
            WHERE username = %s
            AND password_hash = %s
            """,
            (
                clean_username,
                password_hash
            )
        )

        user = cursor.fetchone()

        if user:

            return {
                "success": True,
                "status": "LOGIN_SUCCESS",
                "message": (
                    f"Welcome back, {username}!"
                ),
                "layer": "Both layers passed ✓"
            }

        return {
            "success": False,
            "status": "LOGIN_FAILED",
            "message": (
                "Invalid username or password."
            ),
            "layer": (
                "Layer 1 — Credential Verification"
            )
        }

    except Error as e:

        return {
            "success": False,
            "status": "ERROR",
            "message": str(e)
        }

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# SQL INJECTION TEST
# ============================================================

def test_injection(
    test_input: str,
    ip: str = "unknown"
) -> dict:

    detection = detect_sql_injection(
        test_input
    )

    log_attempt(
        test_input,
        "INJECTION_TEST",
        detection,
        ip
    )

    if detection["is_malicious"]:

        log_attack(
            test_input,
            detection
        )

    return {
        "input": test_input,
        "is_malicious": detection["is_malicious"],
        "risk_level": detection["risk_level"],
        "detail": detection.get(
            "detail",
            "Input is clean"
        ),
        "pattern_matched": detection.get(
            "pattern_matched"
        )
    }


# ============================================================
# SECURITY LOGGING
# ============================================================

def log_attempt(
    input_data: str,
    action: str,
    detection: dict,
    ip: str
):

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO security_log
            (
                input_data,
                action,
                risk_level,
                is_malicious,
                pattern_matched,
                ip_address,
                attempted_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                input_data[:500],
                action,
                detection.get(
                    "risk_level",
                    "NONE"
                ),
                detection.get(
                    "is_malicious",
                    False
                ),
                detection.get(
                    "pattern_matched"
                ),
                ip,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

    except Exception as e:

        print(
            f"[LOG WARNING] "
            f"Could not write security log: {e}"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


def log_attack(
    attack_input: str,
    detection: dict
):

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO detected_attacks
            (
                attack_input,
                pattern_matched,
                risk_level,
                blocked_at
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                attack_input[:500],
                str(
                    detection.get(
                        "pattern_matched",
                        ""
                    )
                ),
                detection.get(
                    "risk_level",
                    "HIGH"
                ),
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

    except Exception as e:

        print(
            f"[ATTACK LOG WARNING] "
            f"Could not write attack log: {e}"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# GET USERS
# ============================================================

def get_users() -> list:

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                username,
                encrypted_email,
                created_at
            FROM users
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "username": row[1],
                "email": decrypt_data(row[2]),
                "created_at": str(row[3])
            }
            for row in rows
        ]

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# GET SECURITY LOGS
# ============================================================

def get_security_logs() -> list:

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                input_data,
                action,
                risk_level,
                is_malicious,
                attempted_at
            FROM security_log
            ORDER BY id DESC
            LIMIT 100
            """
        )

        rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "input": row[1],
                "action": row[2],
                "risk": row[3],
                "malicious": bool(row[4]),
                "time": str(row[5])
            }
            for row in rows
        ]

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# GET DETECTED ATTACKS
# ============================================================

def get_attacks() -> list:

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                attack_input,
                pattern_matched,
                risk_level,
                blocked_at
            FROM detected_attacks
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "input": row[1],
                "pattern": row[2],
                "risk": row[3],
                "time": str(row[4])
            }
            for row in rows
        ]

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ============================================================
# GET STATISTICS
# ============================================================

def get_stats() -> dict:

    conn = None
    cursor = None

    try:

        conn = get_connection()

        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM users"
        )

        total_users = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM security_log"
        )

        total_attempts = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM security_log
            WHERE is_malicious = TRUE
            """
        )

        blocked = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM detected_attacks"
        )

        attacks = cursor.fetchone()[0]

        return {
            "total_users": total_users,
            "total_attempts": total_attempts,
            "blocked_attempts": blocked,
            "attacks_detected": attacks,
            "safe_attempts": (
                total_attempts - blocked
            )
        }

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()
