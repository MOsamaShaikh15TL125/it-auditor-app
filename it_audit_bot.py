#!/usr/bin/env python3
"""
it_audit_bot.py
IT Audit Telegram bot that create:
 - .env (sample placeholders)
 - .mailusr (sample placeholders)
 - it_audit_bot.db (SQLite3 with required tables)
 - it_audit_bot.log (log file)

Security notes:
 - Replace placeholder values in your runtime environment, either in production or development.
 - All developers and community helpers, add .env, .mailusr, *.db, (mkdir) backups/ and *.log to .gitignore before commit to Git or elsewhere for better CS practice.
"""

import os
import sys
import stat
import shutil
import sqlite3
import logging
import hashlib
import getpass
from datetime import datetime, time
from typing import Optional

# Third-party imports
try:
    from dotenv import load_dotenv
except Exception:
    print("Missing dependency: python-dotenv. Install via pip install python-dotenv")
    sys.exit(1)

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, CallbackQuery
    from telegram.ext import (
        Application, CommandHandler, CallbackQueryHandler,
        ContextTypes, MessageHandler, filters
    )
except Exception:
    print("Missing dependency: python-telegram-bot (>=20). Install via pip install python-telegram-bot")
    sys.exit(1)

# Optional dependency for secure TOTP
try:
    import pyotp
except Exception:
    pyotp = None

# ----------------------------
# Configurable constants
# ----------------------------
DB_FILE = "it_audit_bot.db"
LOG_FILE = "it_audit_bot.log"
BACKUP_DIR = "backups"
FIXTURE_ENV = ".env"
FIXTURE_MAIL = ".mailusr"

# ----------------------------
# Fixture & bootstrapping helpers
# ----------------------------
def safe_write_file(path: str, content: str, mode: str = "w", chmod: int = 0o600):
    with open(path, mode) as f:
        f.write(content)
    try:
        os.chmod(path, chmod)
    except Exception:
        # chmod may not be available in other OS or may be restricted
        pass

def generate_file_hash(file_path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def create_dotenv_fixture(path: str = FIXTURE_ENV):
    if os.path.exists(path):
        return
    content = """# Sample .env - replace placeholders with real values (DO NOT COMMIT REAL SECRETS)
BOT_TOKEN=""
ADMIN_USERNAMES="admin1,admin2"
POWERBI_URL=""
EMAIL_RECEIVER="auditor_osama@company.com"
MFA_SECRET=""
COMPLIANCE_GCC=true
COMPLIANCE_NIST=false
COMPLIANCE_E8=false
COMPLIANCE_GDPR=false
COMPLIANCE_CLOUD=false
CLOUD_PROVIDER=AWS #CAN BE CHANGED TO AZURE OR OTHERS LIKE GCP, ALIBABA, ORACLE, IBM
TIMEZONE=UTC
"""
    safe_write_file(path, content)
    print(f"[fixtures] created sample {path}")

def create_mailusr_fixture(path: str = FIXTURE_MAIL):
    if os.path.exists(path):
        return
    content = """# Sample .mailusr - format key:value per line
smtp_host:smtp.example.com
smtp_port:587
smtp_user:smtp_user_osama@example.com
smtp_pass:CHANGE_ME
"""
    safe_write_file(path, content)
    print(f"[fixtures] created sample {path}")

def init_db_schema(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            full_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            start_time DATETIME,
            end_time DATETIME,
            notes TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            command TEXT,
            args TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS erasure_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            requester TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT
        )
    """)
    conn.commit()

def create_db_fixture(path: str = DB_FILE):
    if os.path.exists(path):
        return
    conn = sqlite3.connect(path, check_same_thread=False)
    try:
        init_db_schema(conn)
    finally:
        conn.close()
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    print(f"[fixtures] created DB {path}")

def create_log_fixture(path: str = LOG_FILE):
    if os.path.exists(path):
        return
    safe_write_file(path, "")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    print(f"[fixtures] created log {path}")

def apply_fixtures():
    """Create missing fixtures: .env, .mailusr, DB and log file (idempotent)."""
    created = []
    if not os.path.exists(FIXTURE_ENV):
        create_dotenv_fixture(FIXTURE_ENV)
        created.append(FIXTURE_ENV)
    if not os.path.exists(FIXTURE_MAIL):
        create_mailusr_fixture(FIXTURE_MAIL)
        created.append(FIXTURE_MAIL)
    if not os.path.exists(DB_FILE):
        create_db_fixture(DB_FILE)
        created.append(DB_FILE)
    if not os.path.exists(LOG_FILE):
        create_log_fixture(LOG_FILE)
        created.append(LOG_FILE)
    if not os.path.exists(BACKUP_DIR):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            created.append(BACKUP_DIR)
        except Exception:
            pass
    if created:
        print("[fixtures] applied:", ", ".join(created))
    else:
        print("[fixtures] nothing to create; all fixtures present")

# Apply fixtures BEFORE loading .env so the sample .env is present in runtime (if missing)
apply_fixtures()

# Load environment after fixtures (override doesn't overwrite actual env variables)
load_dotenv(override=False)

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
)
logger = logging.getLogger("it_audit_bot")

# Redaction filter - tries to remove risks of token leakage in message text
class RedactFilter(logging.Filter):
    def __init__(self, secrets: Optional[list] = None):
        super().__init__()
        self.secrets = secrets or []

    def filter(self, record):
        # Redact token from formatted message and args
        try:
            msg = record.getMessage()
            for s in self.secrets:
                if s and s in msg:
                    msg = msg.replace(s, "***REDACTED***")
            record.msg = msg
        except Exception:
            pass
        return True

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MFA_SECRET = os.getenv("MFA_SECRET", "").strip()
ADMIN_USERNAMES = [a.strip() for a in os.getenv("ADMIN_USERNAMES", "").split(",") if a.strip()]
COMPLIANCE_FRAMEWORKS = {
    "GCC": {"enabled": os.getenv("COMPLIANCE_GCC", "true").lower() == "true", "data_localization": True, "retention_days": 90},
    "NIST_US": {"enabled": os.getenv("COMPLIANCE_NIST", "false").lower() == "true", "controls": ["AC-2", "AU-3", "SI-4"]},
    "E8_AU": {"enabled": os.getenv("COMPLIANCE_E8", "false").lower() == "true", "mfa_required": True},
    "EU_GDPR": {"enabled": os.getenv("COMPLIANCE_GDPR", "false").lower() == "true", "right_to_erasure": True, "data_minimization": True},
    "CLOUD": {"enabled": os.getenv("COMPLIANCE_CLOUD", "false").lower() == "true", "encryption": "AES-256", "provider": os.getenv("CLOUD_PROVIDER", "AWS")}
}

# Add redact filter including BOT_TOKEN (if given)
logger.addFilter(RedactFilter(secrets=[BOT_TOKEN]))

logger.info("Starting IT Audit Bot (fixtures applied)")

# ----------------------------
# DB helpers
# ----------------------------
def get_db_connection(db_path: str = DB_FILE) -> Optional[sqlite3.Connection]:
    try:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn
    except Exception as e:
        logger.error(f"DB connection failed: {e}")
        return None

def log_command(user_id: int, command: str, args: str = ""):
    conn = get_db_connection()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO command_logs (user_id, command, args) VALUES (?, ?, ?)", (user_id, command, args))
        conn.commit()
    except Exception as e:
        logger.warning(f"log_command failed: {e}")
    finally:
        conn.close()

# ----------------------------
# Encryption key handling (placeholder - use KMS in production)
# ----------------------------
def get_encryption_key() -> Optional[bytes]:
    """
    Production: fetch from KMS (AWS KMS, Azure Key Vault, etc.)
    Fixture behavior: uses env var CLOUD_ENC_KEY if present, else None
    """
    key = os.getenv("CLOUD_ENC_KEY", "").strip()
    if key:
        return key.encode()
    return None

CLOUD_ENCRYPTION_KEY = get_encryption_key()

from cryptography.fernet import Fernet, InvalidToken

def encrypt_data(plaintext: str) -> str:
    if not CLOUD_ENCRYPTION_KEY or not plaintext:
        return plaintext
    try:
        f = Fernet(CLOUD_ENCRYPTION_KEY)
        return f.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"encrypt_data failed: {e}")
        return plaintext

def decrypt_data(ciphertext: str) -> str:
    if not CLOUD_ENCRYPTION_KEY or not ciphertext:
        return ciphertext
    try:
        f = Fernet(CLOUD_ENCRYPTION_KEY)
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception) as e:
        logger.error(f"decrypt_data failed: {e}")
        return ciphertext

# ----------------------------
# MFA helpers
# ----------------------------
def generate_mfa_code_for_user(user_id: int) -> Optional[str]:
    """
    Use TOTP (pyotp) if MFA_SECRET configured; otherwise return None.
    The best practice is to have per-user secret or enterprise IdP — here we keep a simple approach:
    - If MFA_SECRET env var is set and pyotp available -> use TOTP
    - Otherwise return None (meaning MFA not available)
    """
    if not MFA_SECRET:
        return None
    if pyotp:
        try:
            t = pyotp.TOTP(MFA_SECRET)
            return t.now()
        except Exception as e:
            logger.error(f"pyotp error: {e}")
            return None
    else:
        logger.warning("pyotp not installed; MFA disabled")
        return None

# ----------------------------
# Compliance verification functions
# ----------------------------
def verify_nist_compliance() -> (bool, str):
    if not COMPLIANCE_FRAMEWORKS["NIST_US"]["enabled"]:
        return True, "NIST not enabled"
    missing = []
    if not os.path.exists(DB_FILE):
        missing.append("AC-2: Database not found")
    # logging handlers check
    if not logger.hasHandlers():
        missing.append("AU-3: Logging not configured")
    if missing:
        return False, ", ".join(missing)
    return True, "NIST checks appear present (basic checks)"

def verify_e8_compliance() -> (bool, str):
    if not COMPLIANCE_FRAMEWORKS["E8_AU"]["enabled"]:
        return True, "Essential 8 not enabled"
    missing = []
    if not MFA_SECRET:
        missing.append("MFA not configured")
    # patching/backups checks are environment/process concerns
    if missing:
        return False, ", ".join(missing)
    return True, "Essential 8 basic checks passed (MFA configured)"

# ----------------------------
# GDPR erasure function (best-effort)
# ----------------------------
def perform_gdpr_erasure(user_id: int, requester: str = "self") -> bool:
    """
    Best-effort approach:
    - Anonymize user records in DB
    - Delete command_logs entries
    - Insert an erasure_audit record
    - Remove any backups that contain strings matching user_id (best-effort)
    - Rewrite logs and redact user_id occurrences
    """
    conn = get_db_connection()
    if not conn:
        logger.error("perform_gdpr_erasure: DB connect failed")
        return False
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET username = 'deleted', full_name = 'Deleted User' WHERE user_id = ?", (user_id,))
        cur.execute("UPDATE shifts SET username = 'deleted' WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM command_logs WHERE user_id = ?", (user_id,))
        cur.execute("INSERT INTO erasure_audit (user_id, requester, notes) VALUES (?, ?, ?)",
                    (user_id, requester, "GDPR erasure executed"))
        conn.commit()
    except Exception as e:
        logger.error(f"perform_gdpr_erasure DB operations failed: {e}")
        return False
    finally:
        conn.close()

    # Remove backups that include the user_id string in file (best-effort)
    try:
        if os.path.exists(BACKUP_DIR):
            for fn in os.listdir(BACKUP_DIR):
                full = os.path.join(BACKUP_DIR, fn)
                try:
                    with open(full, "rb") as f:
                        if str(user_id).encode() in f.read():
                            os.remove(full)
                            logger.info(f"Removed backup containing user {user_id}: {fn}")
                except Exception:
                    # Ignore binary files we can't read safely
                    pass
    except Exception as e:
        logger.warning(f"perform_gdpr_erasure backup removal error: {e}")

    # Redact logs (simple approach: rewrite replacing occurrences of user id)
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            redacted = data.replace(str(user_id), "[REDACTED_USERID]")
            safe_write_file(LOG_FILE, redacted, mode="w")
            logger.info(f"Redacted logs for user {user_id}")
    except Exception as e:
        logger.warning(f"perform_gdpr_erasure log redaction failed: {e}")

    return True

# ----------------------------
# Bot helper functions
# ----------------------------
def is_admin(username: Optional[str]) -> bool:
    if not username:
        return False
    return username in ADMIN_USERNAMES

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return
    text = "Welcome to IT Audit Bot.\n"
    if is_admin(user.username):
        text += "Commands: /compliance, /compliance_report, /gdpr_erasure"
    else:
        text += "Commands: /id"
    await update.message.reply_text(text)
    log_command(user.id, "/start")

async def compliance_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.username):
        await update.message.reply_text("🚨 Admins only")
        return
    keyboard = [
        [InlineKeyboardButton("📜 Generate Report", callback_data="compliance_report")],
        [InlineKeyboardButton("🔒 Verify NIST", callback_data="verify_nist")],
        [InlineKeyboardButton("🦘 Check E8", callback_data="verify_e8")],
        [InlineKeyboardButton("🗑️ GDPR Erasure (self)", callback_data="gdpr_erasure")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🔐 Compliance Management:", reply_markup=reply_markup)
    log_command(user.id, "/compliance")

async def handle_verify_nist(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    valid, message = verify_nist_compliance()
    status = "✅ PASS" if valid else "❌ FAIL"
    await query.edit_message_text(f"NIST 800-53 Verification\nStatus: {status}\n{message}")
    user = query.from_user
    log_command(user.id, "verify_nist")

async def handle_verify_e8(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    valid, message = verify_e8_compliance()
    status = "✅ PASS" if valid else "❌ FAIL"
    await query.edit_message_text(f"Essential 8 Verification\nStatus: {status}\n{message}")
    user = query.from_user
    log_command(user.id, "verify_e8")

async def handle_gdpr_erasure(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    user = query.from_user
    # Only proceed if GDPR enabled
    if not COMPLIANCE_FRAMEWORKS["EU_GDPR"]["enabled"]:
        await query.answer("GDPR erasure not enabled in configuration", show_alert=True)
        return
    # For demo: erasure of the requester
    ok = perform_gdpr_erasure(user.id, requester=user.username or str(user.id))
    if ok:
        await query.edit_message_text("✅ GDPR erasure completed for your account (best-effort).")
    else:
        await query.edit_message_text("⚠️ GDPR erasure failed. Check logs.")
    log_command(user.id, "gdpr_erasure")

async def generate_compliance_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.username):
        await update.message.reply_text("🚨 Admin-only command")
        return
    report_lines = []
    report_lines.append("📜 Multi-Compliance Audit Report\n")
    for framework, cfg in COMPLIANCE_FRAMEWORKS.items():
        status = "✅ Enabled" if cfg.get("enabled") else "❌ Disabled"
        report_lines.append(f"- {framework}: {status}")
    if COMPLIANCE_FRAMEWORKS["NIST_US"]["enabled"]:
        nist_valid, nist_msg = verify_nist_compliance()
        report_lines.append("\nNIST 800-53:")
        report_lines.append(f"Status: {'PASS' if nist_valid else 'FAIL'}")
        report_lines.append(f"Details: {nist_msg}")
    if COMPLIANCE_FRAMEWORKS["E8_AU"]["enabled"]:
        e8_valid, e8_msg = verify_e8_compliance()
        report_lines.append("\nEssential 8:")
        report_lines.append(f"Status: {'PASS' if e8_valid else 'FAIL'}")
        report_lines.append(f"Details: {e8_msg}")
    if COMPLIANCE_FRAMEWORKS["EU_GDPR"]["enabled"]:
        report_lines.append("\nGDPR:")
        report_lines.append("Right to Erasure: ✅")
    if COMPLIANCE_FRAMEWORKS["CLOUD"]["enabled"]:
        report_lines.append("\nCloud:")
        report_lines.append(f"Provider: {COMPLIANCE_FRAMEWORKS['CLOUD']['provider']}")
        report_lines.append(f"Encryption: {COMPLIANCE_FRAMEWORKS['CLOUD']['encryption']}")
        report_lines.append(f"Key: {'Present' if CLOUD_ENCRYPTION_KEY else 'Not configured'}")
    # Add some stats
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM shifts")
        shift_count = cur.fetchone()[0]
        report_lines.append(f"\nAudit Stats: Shifts Logged: {shift_count}")
    except Exception:
        report_lines.append("\nAudit Stats: unavailable")
    finally:
        if conn:
            conn.close()
    await update.message.reply_text("\n".join(report_lines))
    log_command(user.id, "compliance_report")

# ----------------------------
# Main application bootstrap
# ----------------------------
def main():
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN is empty. Set it in environment or .env (do not commit real token). Exiting.")
        print("BOT_TOKEN missing. Edit .env or export BOT_TOKEN and restart.")
        sys.exit(1)

    # Initialize DB schema (safe to run multiple times)
    conn = get_db_connection()
    if conn:
        try:
            init_db_schema(conn)
        finally:
            conn.close()

    # Build application
    app = Application.builder().token(BOT_TOKEN).build()

    # Command handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("compliance", compliance_menu))
    app.add_handler(CommandHandler("compliance_report", generate_compliance_report))

    # GDPR erasure direct command (admin only invocation)
    app.add_handler(CommandHandler("gdpr_erasure", lambda u, c: c.application.create_task(generate_compliance_report(u, c))))

    # Callback handlers for InlineKeyboard actions
    app.add_handler(CallbackQueryHandler(handle_verify_nist, pattern="^verify_nist$"))
    app.add_handler(CallbackQueryHandler(handle_verify_e8, pattern="^verify_e8$"))
    app.add_handler(CallbackQueryHandler(handle_gdpr_erasure, pattern="^gdpr_erasure$"))

    # Simple message handler to capture text and log it
    async def echo_and_log(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        if not user:
            return
        text = update.message.text or ""
        # Basic command logging
        log_command(user.id, "message", text[:1000])
        await update.message.reply_text("Message received (logged).")
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo_and_log))

    # Start polling (suitable for small deployments; webhooks can be used as well but reliable for production only)
    logger.info("Bot starting polling...")
    app.run_polling()

if __name__ == "__main__":
    main()

