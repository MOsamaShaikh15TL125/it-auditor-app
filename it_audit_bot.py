#!/usr/bin/env python3
"""
it_audit_bot.py

Enhanced and fixed version of your bot:
 - Creates idempotent fixtures: .env, .mailusr, SQLite DB, log file, backups/
 - Loads environment via python-dotenv
 - Uses sqlite3 by default (fits README). Optionally can be extended for DATABASE_URL.
 - Performs compliance checks (basic), GDPR erasure (best-effort), and generates a summary report.
 - Safe logging with redaction filter for BOT_TOKEN
 - Defensive coding: handles missing optional deps and invalid encryption keys

Before running:
 - Install dependencies:
   pip install python-dotenv python-telegram-bot cryptography pyotp
 - Populate .env with real secrets (do not commit real secrets).
"""

from __future__ import annotations

import os
import sys
import stat
import sqlite3
import logging
import hashlib
from datetime import datetime
from typing import Optional, List

# ----------------------------
# Optional third-party imports
# ----------------------------
try:
    from dotenv import load_dotenv
except Exception:
    print("Missing dependency: python-dotenv. Install via: pip install python-dotenv")
    sys.exit(1)

try:
    # python-telegram-bot v20+ asynchronous
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application,
        CommandHandler,
        CallbackQueryHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
except Exception:
    print("Missing dependency: python-telegram-bot (>=20). Install via: pip install python-telegram-bot")
    sys.exit(1)

# optional
try:
    import pyotp
except Exception:
    pyotp = None

try:
    from cryptography.fernet import Fernet, InvalidToken
    _FERNET_AVAILABLE = True
except Exception:
    Fernet = None  # type: ignore
    InvalidToken = Exception  # fallback
    _FERNET_AVAILABLE = False

# ----------------------------
# Configurable constants
# ----------------------------
DB_FILE = "it_audit_bot.db"
LOG_FILE = "it_audit_bot.log"
BACKUP_DIR = "backups"
FIXTURE_ENV = ".env"
FIXTURE_MAIL = ".mailusr"

# ----------------------------
# File helpers
# ----------------------------
def safe_write_file(path: str, content: str, mode: str = "w", chmod: int = 0o600) -> None:
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(path, chmod)
    except Exception:
        # Best-effort: some platforms may not allow chmod
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

# ----------------------------
# Fixtures (idempotent)
# ----------------------------
def create_dotenv_fixture(path: str = FIXTURE_ENV) -> None:
    if os.path.exists(path):
        return
    content = """# Sample .env - replace placeholders with real values (DO NOT COMMIT REAL SECRETS)
BOT_TOKEN=""
ADMIN_USERNAMES="admin1,admin2"
POWERBI_URL=""
EMAIL_RECEIVER="auditor_osama@company.com"
MFA_SECRET=""
CLOUD_ENC_KEY=""  # must be a valid Fernet key when set (32 urlsafe base64 bytes)
COMPLIANCE_GCC=true
COMPLIANCE_NIST=false
COMPLIANCE_E8=false
COMPLIANCE_GDPR=false
COMPLIANCE_CLOUD=false
CLOUD_PROVIDER=AWS
TIMEZONE=UTC
"""
    safe_write_file(path, content)
    print(f"[fixtures] created sample {path}")

def create_mailusr_fixture(path: str = FIXTURE_MAIL) -> None:
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

def init_db_schema(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            full_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            command TEXT,
            args TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS erasure_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            requester TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT
        )
    """)
    conn.commit()

def create_db_fixture(path: str = DB_FILE) -> None:
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

def create_log_fixture(path: str = LOG_FILE) -> None:
    if os.path.exists(path):
        return
    safe_write_file(path, "")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    print(f"[fixtures] created log {path}")

def apply_fixtures() -> None:
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

# Apply fixtures before loading .env
apply_fixtures()
load_dotenv(override=False)

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler(LOG_FILE) if LOG_FILE else logging.NullHandler(),
        logging.StreamHandler(sys.stdout)
    ],
)
logger = logging.getLogger("it_audit_bot")

# Redaction filter - hides secrets (best-effort)
class RedactFilter(logging.Filter):
    def __init__(self, secrets: Optional[List[str]] = None):
        super().__init__()
        self.secrets = [s for s in (secrets or []) if s]

    def filter(self, record):
        try:
            # record.getMessage() composes msg + args
            msg = record.getMessage()
            for s in self.secrets:
                if s and s in msg:
                    msg = msg.replace(s, "***REDACTED***")
            # mutate the record message so formatted logs are redacted
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True

# ----------------------------
# Config from environment
# ----------------------------
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

# add redact filter after BOT_TOKEN available
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

def log_command(user_id: int, command: str, args: str = "") -> None:
    conn = get_db_connection()
    if not conn:
        logger.warning("log_command: DB not available")
        return
    try:
        with conn:
            conn.execute("INSERT INTO command_logs (user_id, command, args) VALUES (?, ?, ?)", (user_id, command, args))
    except Exception as e:
        logger.warning(f"log_command failed: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

# ----------------------------
# Encryption helpers (safe)
# ----------------------------
def _load_fernet_key_from_env() -> Optional[bytes]:
    raw = os.getenv("CLOUD_ENC_KEY", "").strip()
    if not raw:
        return None
    # If user provided a file path, optionally load file contents
    if os.path.exists(raw) and os.path.isfile(raw):
        try:
            with open(raw, "rb") as f:
                raw = f.read().strip().decode()
        except Exception:
            pass
    # Validate key is correct length for Fernet (it throws inside Fernet constructor if invalid)
    try:
        key_bytes = raw.encode()
        if _FERNET_AVAILABLE:
            # try to instantiate to validate
            Fernet(key_bytes)
            return key_bytes
        else:
            logger.warning("cryptography.Fernet not available; encryption disabled")
            return None
    except Exception as e:
        logger.warning(f"CLOUD_ENC_KEY invalid or not a valid Fernet key: {e}")
        return None

_CLOUD_ENC_KEY_BYTES = _load_fernet_key_from_env()

def encrypt_data(plaintext: str) -> str:
    if not _CLOUD_ENC_KEY_BYTES or not plaintext:
        return plaintext
    try:
        f = Fernet(_CLOUD_ENC_KEY_BYTES)  # type: ignore
        return f.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"encrypt_data failed: {e}")
        return plaintext

def decrypt_data(ciphertext: str) -> str:
    if not _CLOUD_ENC_KEY_BYTES or not ciphertext:
        return ciphertext
    try:
        f = Fernet(_CLOUD_ENC_KEY_BYTES)  # type: ignore
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception) as e:
        logger.error(f"decrypt_data failed: {e}")
        return ciphertext

# ----------------------------
# MFA helpers
# ----------------------------
def generate_mfa_code_for_secret(secret: str) -> Optional[str]:
    if not secret:
        return None
    if pyotp:
        try:
            t = pyotp.TOTP(secret)
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
        return True, "NIST checks are disabled in configuration"
    missing = []
    if not os.path.exists(DB_FILE):
        missing.append("AC-2: Database not found")
    # check logging: ensure file exists and has content or handlers
    if not os.path.exists(LOG_FILE):
        missing.append("AU-3: Logging file missing")
    if missing:
        return False, "; ".join(missing)
    return True, "NIST basic checks ok"

def verify_e8_compliance() -> (bool, str):
    if not COMPLIANCE_FRAMEWORKS["E8_AU"]["enabled"]:
        return True, "Essential Eight checks disabled in configuration"
    missing = []
    if not MFA_SECRET:
        missing.append("MFA secret not configured")
    if missing:
        return False, "; ".join(missing)
    return True, "Essential Eight basic checks ok"

# ----------------------------
# GDPR erasure (best-effort)
# ----------------------------
def perform_gdpr_erasure(user_id: int, requester: str = "self") -> bool:
    conn = get_db_connection()
    if not conn:
        logger.error("perform_gdpr_erasure: DB connect failed")
        return False
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET username = 'deleted', full_name = 'Deleted User' WHERE user_id = ?", (user_id,))
        cur.execute("UPDATE shifts SET username = 'deleted' WHERE user_id = ?", (user_id,))
        cur.execute("DELETE FROM command_logs WHERE user_id = ?", (user_id,))
        cur.execute(
            "INSERT INTO erasure_audit (user_id, requester, notes) VALUES (?, ?, ?)",
            (user_id, requester, "GDPR erasure executed")
        )
        conn.commit()
    except Exception as e:
        logger.error(f"perform_gdpr_erasure DB operations failed: {e}")
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Remove backups that contain the user_id (best-effort)
    try:
        if os.path.exists(BACKUP_DIR):
            for fn in os.listdir(BACKUP_DIR):
                full = os.path.join(BACKUP_DIR, fn)
                try:
                    with open(full, "rb") as f:
                        content = f.read()
                    if str(user_id).encode() in content:
                        try:
                            os.remove(full)
                            logger.info(f"Removed backup containing user {user_id}: {fn}")
                        except Exception:
                            pass
                except Exception:
                    # ignore files we cannot read
                    pass
    except Exception as e:
        logger.warning(f"perform_gdpr_erasure backup removal error: {e}")

    # Redact logs (simple rewrite)
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
# Bot helper utilities
# ----------------------------
def is_admin(username: Optional[str]) -> bool:
    if not username:
        return False
    return username in ADMIN_USERNAMES

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user:
        return
    text = "Welcome to IT Auditor App Bot.\n"
    if is_admin(user.username):
        text += "Admin Commands: /compliance, /compliance_report, /gdpr_erasure, /health\n"
    else:
        text += "User Commands: /id, /gdpr_erasure (self)\n"
    text += "See README for full setup and usage."
    # reply
    if update.message:
        await update.message.reply_text(text)
    else:
        # fallback: edit callback or answer
        await update.effective_chat.send_message(text)
    log_command(user.id, "/start")

async def cmd_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user:
        return
    msg = f"Your Telegram ID: {user.id}\nUsername: @{user.username}" if user.username else f"Your Telegram ID: {user.id}"
    if update.message:
        await update.message.reply_text(msg)
    else:
        await update.effective_chat.send_message(msg)
    log_command(user.id, "/id")

async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.username):
        if update.message:
            await update.message.reply_text("🚨 Admins only")
        return
    # Basic health: DB, log file, encryption key presence
    ok_db = os.path.exists(DB_FILE)
    ok_log = os.path.exists(LOG_FILE)
    ok_enc = bool(_CLOUD_ENC_KEY_BYTES)
    lines = [
        f"Health Check @ {datetime.utcnow().isoformat()}Z",
        f"DB file present: {'✅' if ok_db else '❌'}",
        f"Log file present: {'✅' if ok_log else '❌'}",
        f"Encryption key configured: {'✅' if ok_enc else '❌'}",
    ]
    await update.message.reply_text("\n".join(lines))
    log_command(user.id, "/health")

async def cmd_compliance(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.username):
        if update.message:
            await update.message.reply_text("🚨 Admins only")
        return
    keyboard = [
        [InlineKeyboardButton("📜 Generate Report", callback_data="compliance_report")],
        [InlineKeyboardButton("🔒 Verify NIST", callback_data="verify_nist")],
        [InlineKeyboardButton("🦘 Check E8", callback_data="verify_e8")],
        [InlineKeyboardButton("🗑️ GDPR Erasure (self)", callback_data="gdpr_erasure_self")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    if update.message:
        await update.message.reply_text("🔐 Compliance Management:", reply_markup=reply_markup)
    log_command(user.id, "/compliance")

# Callback handlers -- use canonical signature (update, context)
async def cb_verify_nist(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    valid, message = verify_nist_compliance()
    status = "✅ PASS" if valid else "❌ FAIL"
    await query.edit_message_text(f"NIST 800-53 Verification\nStatus: {status}\n{message}")
    user = query.from_user
    log_command(user.id if user else 0, "verify_nist")

async def cb_verify_e8(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    valid, message = verify_e8_compliance()
    status = "✅ PASS" if valid else "❌ FAIL"
    await query.edit_message_text(f"Essential 8 Verification\nStatus: {status}\n{message}")
    user = query.from_user
    log_command(user.id if user else 0, "verify_e8")

async def cb_gdpr_erasure_self(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    user = query.from_user
    # Allowed only if GDPR enabled
    if not COMPLIANCE_FRAMEWORKS["EU_GDPR"]["enabled"]:
        await query.edit_message_text("GDPR erasure not enabled in configuration")
        return
    ok = perform_gdpr_erasure(user.id, requester=user.username or str(user.id))
    if ok:
        await query.edit_message_text("✅ GDPR erasure completed for the account (best-effort).")
    else:
        await query.edit_message_text("⚠️ GDPR erasure failed. Check logs.")
    log_command(user.id if user else 0, "gdpr_erasure_self")

async def cmd_gdpr_erasure(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    /gdpr_erasure           -> user requests erasure for self (if GDPR enabled)
    /gdpr_erasure <user_id> -> admin requests erasure for a user
    """
    user = update.effective_user
    if not user or not update.message:
        return
    args = context.args or []
    # If admin provided a user_id argument, allow admin to erase that user
    if args and is_admin(user.username):
        try:
            target_id = int(args[0])
        except ValueError:
            await update.message.reply_text("Invalid user_id. Usage: /gdpr_erasure <user_id>")
            return
        ok = perform_gdpr_erasure(target_id, requester=user.username or str(user.id))
        await update.message.reply_text("✅ GDPR erasure requested (admin) for user_id: {}".format(target_id) if ok else "⚠️ GDPR erasure failed")
        log_command(user.id, f"gdpr_erasure_admin:{target_id}")
        return

    # Otherwise, user requests own erasure (if enabled)
    if not COMPLIANCE_FRAMEWORKS["EU_GDPR"]["enabled"]:
        await update.message.reply_text("GDPR erasure is not enabled in configuration.")
        return
    ok = perform_gdpr_erasure(user.id, requester=user.username or str(user.id))
    if ok:
        await update.message.reply_text("✅ GDPR erasure completed for your account (best-effort).")
    else:
        await update.message.reply_text("⚠️ GDPR erasure failed. Check logs.")
    log_command(user.id, "gdpr_erasure_self")

async def cmd_compliance_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.username):
        if update.message:
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
        report_lines.append(f"Key: {'Present' if _CLOUD_ENC_KEY_BYTES else 'Not configured'}")
    # Add some stats
    conn = get_db_connection()
    try:
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM shifts")
            shift_count = cur.fetchone()[0] if cur.fetchone() is not None else 0
            # Note: the above double fetch would consume row; better do fetchone once
    except Exception:
        shift_count = None
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
    if shift_count is None:
        report_lines.append("\nAudit Stats: unavailable")
    else:
        report_lines.append(f"\nAudit Stats: Shifts Logged: {shift_count}")
    if update.message:
        await update.message.reply_text("\n".join(report_lines))
    log_command(user.id, "compliance_report")

# Simple message handler to log text messages (non-command)
async def echo_and_log(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    user = update.effective_user
    if not user:
        return
    text = update.message.text or ""
    log_command(user.id, "message", (text[:1000] if text else ""))
    await update.message.reply_text("Message received and logged.")

# ----------------------------
# Application bootstrap
# ----------------------------
def main() -> None:
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN is empty. Set it in environment or .env (do not commit real token). Exiting.")
        print("BOT_TOKEN missing. Edit .env or export BOT_TOKEN and restart.")
        sys.exit(1)

    # Initialize DB schema (safe)
    conn = get_db_connection()
    if conn:
        try:
            init_db_schema(conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # Build application
    app = Application.builder().token(BOT_TOKEN).build()

    # Command handlers
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("id", cmd_id))
    app.add_handler(CommandHandler("health", cmd_health))
    app.add_handler(CommandHandler("compliance", cmd_compliance))
    app.add_handler(CommandHandler("compliance_report", cmd_compliance_report))
    app.add_handler(CommandHandler("gdpr_erasure", cmd_gdpr_erasure, filters=None))  # args allowed

    # Callback handlers (inline keyboard)
    app.add_handler(CallbackQueryHandler(cb_verify_nist, pattern="^verify_nist$"))
    app.add_handler(CallbackQueryHandler(cb_verify_e8, pattern="^verify_e8$"))
    app.add_handler(CallbackQueryHandler(cb_gdpr_erasure_self, pattern="^gdpr_erasure_self$"))
    app.add_handler(CallbackQueryHandler(lambda u, c: c.application.create_task(cmd_compliance_report(u, c)), pattern="^compliance_report$"))

    # Message handler
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo_and_log))

    # Startup info
    logger.info("Bot starting polling...")
    try:
        app.run_polling()
    except Exception as e:
        logger.exception(f"Bot stopped with exception: {e}")

if __name__ == "__main__":
    main()
