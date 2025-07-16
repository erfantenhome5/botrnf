import asyncio
import hashlib
import json
import logging
import os
import random
import re
import shutil
import traceback
import uuid  # Added for generating random usernames
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import sentry_sdk
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.types import Event, Hint
from telethon import Button, TelegramClient, errors, events
from telethon.sessions import StringSession
from telethon.tl import functions
from telethon.tl.functions.channels import CreateChannelRequest, InviteToChannelRequest
from telethon.tl.types import Message

# --- Basic Logging Setup ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot_activity.log"),
        logging.StreamHandler()
    ]
)
LOGGER = logging.getLogger(__name__)

# --- Environment Loading ---
# This script now consistently uses os.getenv, which works in any environment
# as long as the variables are set before the script runs.
load_dotenv()
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
SENTRY_DSN = os.getenv("SENTRY_DSN")
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID")
MASTER_PASSWORD_HASH = os.getenv("MASTER_PASSWORD_HASH")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


if not all([API_ID, API_HASH, BOT_TOKEN, ENCRYPTION_KEY, ADMIN_USER_ID]):
    raise ValueError("Missing required environment variables. Ensure API_ID, API_HASH, BOT_TOKEN, ENCRYPTION_KEY, and ADMIN_USER_ID are set.")

API_ID = int(API_ID)
ADMIN_USER_ID = int(ADMIN_USER_ID)

# For Colab, the SESSIONS_DIR path will be set before running the script.
# For other environments, it defaults to a local 'sessions' folder.
SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", "sessions"))
SESSIONS_DIR.mkdir(exist_ok=True, parents=True)

# --- Global Proxy Loading Function ---
def load_proxies_from_file(proxy_file_path: str) -> List[Dict]:
    """
    Loads proxies from the specified file.
    Expected format: IP:PORT
    """
    proxy_list = []
    try:
        with open(proxy_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    # UPDATED: Split into two parts for IP auth
                    host, port = line.split(':', 1)
                    proxy_list.append({
                        'proxy_type': 'http',
                        'addr': host,
                        'port': int(port)
                    })
                except ValueError:
                    LOGGER.warning(f"Skipping malformed proxy line: {line}. Expected format is IP:PORT.")
        LOGGER.info(f"Loaded {len(proxy_list)} proxies from {proxy_file_path}.")
    except FileNotFoundError:
        LOGGER.warning(f"Proxy file '{proxy_file_path}' not found.")
    return proxy_list

# --- Centralized Configuration ---
class Config:
    """Holds all configurable values and UI strings for the bot."""
    # Bot Settings
    MAX_CONCURRENT_WORKERS = 5
    GROUPS_TO_CREATE = 50
    MIN_SLEEP_SECONDS = 60
    MAX_SLEEP_SECONDS = 240
    PROXY_FILE = "proxy.txt"
    PROXY_TIMEOUT = 15

    # --- UI Text & Buttons (All in Persian) ---
    BTN_MANAGE_ACCOUNTS = "👤 مدیریت حساب‌ها"
    BTN_SERVER_STATUS = "📊 وضعیت سرور"
    BTN_HELP = "ℹ️ راهنما"
    BTN_ADD_ACCOUNT = "➕ افزودن حساب (API)"
    BTN_ADD_ACCOUNT_SELENIUM = "✨ افزودن حساب (مرورگر امن)"
    BTN_BACK = "⬅️ بازگشت"
    BTN_START_PREFIX = "🟢 شروع برای"
    BTN_STOP_PREFIX = "⏹️ توقف برای"
    BTN_DELETE_PREFIX = "🗑️ حذف"
    BTN_SET_KEYWORDS = "📝 تنظیم کلمات کلیدی AI"

    # --- Messages (All in Persian) ---
    MSG_WELCOME = "**🤖 به ربات سازنده گروه خوش آمدید!**"
    MSG_ACCOUNT_MENU_HEADER = "👤 **مدیریت حساب‌ها**\n\nاز این منو می‌توانید حساب‌های خود را مدیریت کرده و عملیات ساخت گروه را برای هرکدام آغاز یا متوقف کنید."
    MSG_HELP_TEXT = (
        "**راهنمای جامع ربات**\n\n"
        "این ربات به شما اجازه می‌دهد تا با چندین حساب تلگرام به صورت همزمان گروه‌های جدید بسازید.\n\n"
        f"**{BTN_MANAGE_ACCOUNTS}**\n"
        "در این بخش می‌توانید حساب‌های خود را مدیریت کنید:\n"
        f"  - `{BTN_ADD_ACCOUNT}`: یک شماره تلفن جدید با روش API اضافه کنید.\n"
        f"  - `{BTN_ADD_ACCOUNT_SELENIUM}`: یک شماره تلفن جدید با روش شبیه‌سازی مرورگر اضافه کنید (امنیت بالاتر).\n"
        f"  - `{BTN_START_PREFIX} [نام حساب]`: عملیات ساخت گروه را برای حساب مشخص شده آغاز می‌کند.\n"
        f"  - `{BTN_STOP_PREFIX} [نام حساب]`: عملیات در حال اجرا برای یک حساب را متوقف می‌کند.\n"
        f"  - `{BTN_DELETE_PREFIX} [نام حساب]`: یک حساب و تمام اطلاعات آن را برای همیشه حذف می‌کند.\n\n"
        f"**{BTN_SET_KEYWORDS}**\n"
        "کلمات کلیدی مورد نظر خود را برای تولید محتوای هوش مصنوعی تنظیم کنید.\n\n"
        f"**{BTN_SERVER_STATUS}**\n"
        "این گزینه اطلاعات لحظه‌ای درباره وضعیت ربات را نمایش می‌دهد."
    )
    MSG_PROMPT_MASTER_PASSWORD = "🔑 لطفاً برای دسترسی به ربات، رمز عبور اصلی را وارد کنید:"
    MSG_INCORRECT_MASTER_PASSWORD = "❌ رمز عبور اشتباه است. لطفاً دوباره تلاش کنید."
    MSG_BROWSER_RUNNING = "⏳ در حال آماده‌سازی مرورگر امن... این کار ممکن است چند لحظه طول بکشد."
    MSG_PROMPT_KEYWORDS = "📝 لطفاً کلمات کلیدی مورد نظر خود را برای تولید محتوای هوش مصنوعی وارد کنید. کلمات را با کاما (,) از هم جدا کنید.\n\nمثال: موفقیت, بازاریابی, ارز دیجیتال, فروش آنلاین"
    MSG_KEYWORDS_SET = "✅ کلمات کلیدی شما با موفقیت ذخیره شد."
    MSG_AWAITING_APPROVAL = "⏳ درخواست دسترسی شما برای ادمین ارسال شد. لطفاً منتظر تایید بمانید."
    MSG_USER_APPROVED = "✅ درخواست شما تایید شد! برای شروع /start را بزنید."
    MSG_USER_DENIED = "❌ متاسفانه درخواست دسترسی شما رد شد."


# The SessionManager class is now defined here to make the script self-contained.
class SessionManager:
    """Manages encrypted user session files."""
    def __init__(self, fernet: Fernet, directory: Path):
        self._fernet = fernet
        self._dir = directory
        self._user_sessions_dir = self._dir / "user_sessions"
        self._user_sessions_dir.mkdir(exist_ok=True)

    def _get_user_dir(self, user_id: int) -> Path:
        """Gets or creates the directory for a specific user."""
        user_dir = self._user_sessions_dir / str(user_id)
        user_dir.mkdir(exist_ok=True)
        return user_dir

    def get_user_accounts(self, user_id: int) -> List[str]:
        """Lists all account names for a given user."""
        user_dir = self._get_user_dir(user_id)
        return [f.stem for f in user_dir.glob("*.session")]

    def save_session_string(self, user_id: int, name: str, session_string: str) -> None:
        """Saves an encrypted session string to a file."""
        user_dir = self._get_user_dir(user_id)
        session_file = user_dir / f"{name}.session"
        encrypted_session = self._fernet.encrypt(session_string.encode())
        session_file.write_bytes(encrypted_session)

    def load_session_string(self, user_id: int, name: str) -> Optional[str]:
        """Loads and decrypts a session string from a file."""
        user_dir = self._get_user_dir(user_id)
        session_file = user_dir / f"{name}.session"
        if not session_file.exists():
            return None
        try:
            encrypted_session = session_file.read_bytes()
            decrypted_session = self._fernet.decrypt(encrypted_session)
            return decrypted_session.decode()
        except (InvalidToken, IOError):
            LOGGER.error(f"Could not load or decrypt session for {name} of user {user_id}.")
            return None

    def delete_session_file(self, user_id: int, name: str) -> bool:
        """Deletes a session file."""
        user_dir = self._get_user_dir(user_id)
        session_file = user_dir / f"{name}.session"
        if session_file.exists():
            session_file.unlink()
            return True
        return False


class GroupCreatorBot:
    """A class to encapsulate the bot's logic for managing multiple accounts."""

    def __init__(self, session_manager) -> None:
        """Initializes the bot instance and the encryption engine."""
        self.bot = TelegramClient('bot_session', API_ID, API_HASH)
        self.user_sessions: Dict[int, Dict[str, Any]] = {}
        self.active_workers: Dict[str, asyncio.Task] = {}
        self.worker_semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_WORKERS)
        self.counts_file = SESSIONS_DIR / "group_counts.json"
        self.group_counts = self._load_group_counts()
        self.proxies = load_proxies_from_file(Config.PROXY_FILE)
        self.account_proxy_file = SESSIONS_DIR / "account_proxies.json"
        self.account_proxies = self._load_account_proxies()
        self.known_users_file = SESSIONS_DIR / "known_users.json"
        self.known_users = self._load_known_users()
        self.pending_users_file = SESSIONS_DIR / "pending_users.json"
        self.pending_users = self._load_pending_users()
        self.created_groups_file = SESSIONS_DIR / "created_groups.json"
        self.created_groups = self._load_created_groups()
        self.active_workers_file = SESSIONS_DIR / "active_workers.json"
        self.active_workers_state = self._load_active_workers_state()
        self.keywords_file = SESSIONS_DIR / "keywords.json"
        self.user_keywords = self._load_user_keywords()
        try:
            fernet = Fernet(ENCRYPTION_KEY.encode())
            # Initialize the session manager instance
            self.session_manager = session_manager(fernet, SESSIONS_DIR)
        except (ValueError, TypeError):
            raise ValueError("Invalid ENCRYPTION_KEY. Please generate a valid key.")

        self._initialize_sentry()

    # --- Sentry Methods ---
    def _initialize_sentry(self):
        """Initializes the Sentry SDK with instance-aware hooks."""
        if not SENTRY_DSN:
            return

        def before_send_hook(event: Event, hint: Hint) -> Optional[Event]:
            if 'log_record' in hint:
                log_record = hint['log_record']
                if log_record.levelno == logging.DEBUG and log_record.name.startswith('telethon'):
                    message = log_record.getMessage()
                    noisy_patterns = [
                        "Assigned msg_id", "Encrypting", "Encrypted messages put in a queue",
                        "Waiting for messages to send", "Handling pong", "Receiving items from the network",
                        "Handling gzipped data", "Handling update", "Handling RPC result",
                        "stopped chain of propagation"
                    ]
                    for pattern in noisy_patterns:
                        if pattern in message:
                            return None
            return event

        sentry_logging = LoggingIntegration(
            level=logging.INFO,
            event_level=logging.ERROR,
            sentry_logs_level=logging.DEBUG
        )

        sentry_options = {
            "dsn": SENTRY_DSN,
            "integrations": [sentry_logging],
            "traces_sample_rate": 1.0,
            "_experiments": {"enable_logs": True},
            "before_send": before_send_hook,
        }

        if self.proxies:
            sentry_proxy = random.choice(self.proxies)
            # UPDATED: Proxy URL without authentication
            proxy_url = f"http://{sentry_proxy['addr']}:{sentry_proxy['port']}"
            sentry_options["http_proxy"] = proxy_url
            sentry_options["https_proxy"] = proxy_url
            LOGGER.info(f"Sentry will use proxy: {sentry_proxy['addr']}:{sentry_proxy['port']}")
        else:
            LOGGER.info("Sentry will not use a proxy (none found).")

        sentry_sdk.init(**sentry_options)
        LOGGER.info("Sentry initialized for error reporting.")

    # --- Proxy Helpers ---
    def _load_account_proxies(self) -> Dict[str, Dict]:
        if not self.account_proxy_file.exists():
            return {}
        try:
            with self.account_proxy_file.open("r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            LOGGER.error("Could not read or parse account_proxies.json. Starting with empty assignments.")
            return {}

    def _save_account_proxies(self) -> None:
        try:
            with self.account_proxy_file.open("w") as f:
                json.dump(self.account_proxies, f, indent=4)
        except IOError:
            LOGGER.error("Could not save account_proxies.json.")

    def _get_available_proxy(self) -> Optional[Dict]:
        if not self.proxies:
            return None
        # UPDATED: Unique key for proxy without username
        assigned_proxy_keys = {
            (p['addr'], p['port'])
            for p in self.account_proxies.values() if p
        }
        for proxy in self.proxies:
            proxy_key = (proxy['addr'], proxy['port'])
            if proxy_key not in assigned_proxy_keys:
                LOGGER.info(f"Found available proxy: {proxy['addr']}:{proxy['port']}")
                return proxy
        LOGGER.warning("All proxies are currently assigned. No available proxy found.")
        return None

    # --- Data Store Helpers ---
    def _load_json_file(self, file_path: Path, default_type: Any = {}) -> Any:
        if not file_path.exists():
            return default_type
        try:
            with file_path.open("r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            LOGGER.error(f"Could not read or parse {file_path.name}. Starting with empty data.")
            return default_type

    def _save_json_file(self, data: Any, file_path: Path) -> None:
        try:
            with file_path.open("w") as f:
                json.dump(data, f, indent=4)
        except IOError:
            LOGGER.error(f"Could not save {file_path.name}.")

    def _load_group_counts(self) -> Dict[str, int]:
        return self._load_json_file(self.counts_file, {})

    def _save_group_counts(self) -> None:
        self._save_json_file(self.group_counts, self.counts_file)

    def _load_user_keywords(self) -> Dict[str, List[str]]:
        return self._load_json_file(self.keywords_file, {})

    def _save_user_keywords(self) -> None:
        self._save_json_file(self.user_keywords, self.keywords_file)

    def _load_known_users(self) -> List[int]:
        return self._load_json_file(self.known_users_file, [])

    def _save_known_users(self) -> None:
        self._save_json_file(self.known_users, self.known_users_file)

    def _load_pending_users(self) -> List[int]:
        return self._load_json_file(self.pending_users_file, [])

    def _save_pending_users(self) -> None:
        self._save_json_file(self.pending_users, self.pending_users_file)

    def _load_created_groups(self) -> Dict[str, Dict]:
        return self._load_json_file(self.created_groups_file, {})

    def _save_created_groups(self) -> None:
        self._save_json_file(self.created_groups, self.created_groups_file)

    def _get_group_count(self, worker_key: str) -> int:
        return self.group_counts.get(worker_key, 0)

    def _set_group_count(self, worker_key: str, count: int) -> None:
        self.group_counts[worker_key] = count
        self._save_group_counts()

    def _remove_group_count(self, worker_key: str) -> None:
        if worker_key in self.group_counts:
            del self.group_counts[worker_key]
            self._save_group_counts()

    # --- User and Worker State Management ---
    def _load_active_workers_state(self) -> Dict[str, Dict]:
        if not self.active_workers_file.exists():
            return {}
        try:
            with self.active_workers_file.open("r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            LOGGER.error("Could not read active_workers.json.")
            return {}

    def _save_active_workers_state(self) -> None:
        try:
            with self.active_workers_file.open("w") as f:
                json.dump(self.active_workers_state, f, indent=4)
        except IOError:
            LOGGER.error("Could not save active_workers.json.")

    async def _broadcast_message(self, message_text: str):
        LOGGER.info(f"Broadcasting message to {len(self.known_users)} users.")
        for user_id in self.known_users:
            try:
                await self.bot.send_message(user_id, message_text)
                await asyncio.sleep(0.1)
            except (errors.UserIsBlockedError, errors.InputUserDeactivatedError):
                LOGGER.warning(f"User {user_id} has blocked the bot or is deactivated. Cannot send message.")
            except Exception as e:
                LOGGER.error(f"Error sending message to {user_id}: {e}")

    async def _create_login_client(self, proxy: Optional[Dict]) -> Optional[TelegramClient]:
        session = StringSession()
        device_params = random.choice([{'device_model': 'iPhone 14 Pro Max', 'system_version': '17.5.1'}, {'device_model': 'Samsung Galaxy S24 Ultra', 'system_version': 'SDK 34'}])

        try:
            proxy_info = f"with proxy {proxy['addr']}:{proxy['port']}" if proxy else "without proxy"
            LOGGER.debug(f"Attempting login connection {proxy_info}")
            client = TelegramClient(session, API_ID, API_HASH, proxy=proxy, timeout=Config.PROXY_TIMEOUT, **device_params)
            await client.connect()
            return client
        except Exception as e:
            LOGGER.error(f"Login connection {proxy_info} failed: {e}")
            return None

    async def _create_worker_client(self, session_string: str, proxy: Optional[Dict]) -> Optional[TelegramClient]:
        session = StringSession(session_string)
        device_params = random.choice([{'device_model': 'iPhone 14 Pro Max', 'system_version': '17.5.1'}, {'device_model': 'Samsung Galaxy S24 Ultra', 'system_version': 'SDK 34'}])

        client = TelegramClient(
            session, API_ID, API_HASH, proxy=proxy, timeout=Config.PROXY_TIMEOUT,
            device_model=device_params['device_model'], system_version=device_params['system_version']
        )

        try:
            proxy_info = f"with proxy {proxy['addr']}:{proxy['port']}" if proxy else "without proxy"
            LOGGER.debug(f"Attempting worker connection {proxy_info}")
            await client.connect()
            LOGGER.info(f"Worker connected successfully {proxy_info}")
            return client
        except Exception as e:
            LOGGER.error(f"Worker connection {proxy_info} failed: {e}")
            sentry_sdk.capture_exception(e)
            if isinstance(e, errors.AuthKeyUnregisteredError):
                raise
            return None

    async def _send_request_with_reconnect(self, client: TelegramClient, request: Any, account_name: str) -> Any:
        try:
            if not client.is_connected():
                LOGGER.warning(f"Client for '{account_name}' is disconnected. Reconnecting...")
                await client.connect()
                if client.is_connected():
                    LOGGER.info(f"Client for '{account_name}' reconnected successfully.")
                else:
                    LOGGER.error(f"Failed to reconnect client for '{account_name}'.")
                    raise ConnectionError("Client reconnection failed.")
            return await client(request)
        except ConnectionError as e:
            LOGGER.error(f"Connection error for '{account_name}' even after check: {e}")
            sentry_sdk.capture_exception(e)
            raise
        except Exception as e:
            LOGGER.error(f"Unexpected error sending request for '{account_name}': {e}")
            sentry_sdk.capture_exception(e)
            raise

    # --- Dynamic UI Builder ---
    def _build_main_menu(self) -> List[List[Button]]:
        return [
            [Button.text(Config.BTN_MANAGE_ACCOUNTS)],
            [Button.text(Config.BTN_SET_KEYWORDS)],
            [Button.text(Config.BTN_SERVER_STATUS), Button.text(Config.BTN_HELP)],
        ]

    def _build_accounts_menu(self, user_id: int) -> List[List[Button]]:
        accounts = self.session_manager.get_user_accounts(user_id)
        keyboard = []
        if not accounts:
            keyboard.append([Button.text("هنوز هیچ حسابی اضافه نشده است.")])
        else:
            for acc_name in accounts:
                worker_key = f"{user_id}:{acc_name}"
                if worker_key in self.active_workers:
                    keyboard.append([Button.text(f"{Config.BTN_STOP_PREFIX} {acc_name}")])
                else:
                    keyboard.append([
                        Button.text(f"{Config.BTN_START_PREFIX} {acc_name}"),
                        Button.text(f"{Config.BTN_DELETE_PREFIX} {acc_name}")
                    ])
        keyboard.append([
            Button.text(Config.BTN_ADD_ACCOUNT),
            Button.text(Config.BTN_ADD_ACCOUNT_SELENIUM)
        ])
        keyboard.append([Button.text(Config.BTN_BACK)])
        return keyboard

    async def _generate_persian_messages(self, user_id: int) -> List[str]:
        """Generates 20 Persian messages using user-defined keywords, with proxy retries."""
        if not GEMINI_API_KEY:
            LOGGER.warning("GEMINI_API_KEY not set. Skipping message generation.")
            return []

        keywords = self.user_keywords.get(str(user_id), ["زندگی", "خدا", "موفقیت"])
        prompt = (
            f"ایجاد ۲۰ پیام یا نقل قول منحصر به فرد و عمیق به زبان فارسی. "
            f"این پیام‌ها باید درباره این موضوعات باشند: {', '.join(keywords)}. "
            "لطفا پاسخ را در قالب یک آرایه JSON از رشته‌ها برگردانید. مثال: "
            '["پیام اول", "پیام دوم", ...]'
            "فقط و فقط آرایه JSON را بدون هیچ متن اضافی، توضیحات یا قالب‌بندی دیگری برگردانید."
        )
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"responseMimeType": "application/json"}}
        headers = {'Content-Type': 'application/json'}

        # --- START: Resilient Proxy Retry Logic ---
        proxies_to_try = list(self.proxies)
        random.shuffle(proxies_to_try)
        proxies_to_try.append(None) # Add None for a direct connection attempt as a fallback

        for attempt_num, proxy_choice in enumerate(proxies_to_try):
            proxy_mount = None
            log_proxy_info = "direct connection"
            if proxy_choice:
                # UPDATED: Proxy URL for httpx without authentication
                proxy_url = f"http://{proxy_choice['addr']}:{proxy_choice['port']}"
                proxy_mount = {"all://": proxy_url}
                log_proxy_info = f"proxy {proxy_choice['addr']}"

            LOGGER.info(f"Attempt {attempt_num + 1}/{len(proxies_to_try)}: Using {log_proxy_info} for Gemini.")

            try:
                async with httpx.AsyncClient(proxies=proxy_mount, timeout=40.0) as client:
                    response = await client.post(api_url, json=payload, headers=headers)
                    response.raise_for_status()
                    data = response.json()

                    if data.get("candidates") and data["candidates"][0].get("content", {}).get("parts"):
                        json_text = data["candidates"][0]["content"]["parts"][0]["text"]
                        messages = json.loads(json_text)
                        if isinstance(messages, list) and all(isinstance(item, str) for item in messages):
                            LOGGER.info(f"Successfully generated {len(messages)} messages from Gemini on attempt {attempt_num + 1}.")
                            return messages # Success, exit the function
                        else:
                            LOGGER.warning(f"Gemini API returned an unexpected format inside JSON: {messages}")
                            break # Don't retry on malformed data
                    else:
                        LOGGER.warning(f"Unexpected Gemini API response structure: {data}")
                        break # Don't retry on malformed data

            except httpx.RequestError as e:
                LOGGER.error(f"Attempt {attempt_num + 1} failed: {e}.")
                if attempt_num < len(proxies_to_try) - 1:
                    await asyncio.sleep(1) # Wait a second before next attempt
                    continue # Try next proxy
                else:
                    LOGGER.error("All proxy attempts and direct connection failed for Gemini API.")
                    sentry_sdk.capture_exception(e)
            except json.JSONDecodeError as e:
                LOGGER.error(f"Error decoding JSON from Gemini response (attempt {attempt_num + 1}): {e}.")
                sentry_sdk.capture_exception(e)
                break # Non-retryable error
            except Exception as e:
                LOGGER.error(f"An unexpected error occurred during message generation (attempt {attempt_num + 1}): {e}.")
                sentry_sdk.capture_exception(e)
                break # Non-retryable error
        # --- END: Resilient Proxy Retry Logic ---

        return [] # Return empty list if all attempts fail

    async def _simulate_conversation(self, user_id: int, group_id: int):
        user_accounts = self.session_manager.get_user_accounts(user_id)
        if len(user_accounts) < 2:
            LOGGER.warning(f"Cannot simulate conversation for user {user_id}, not enough accounts ({len(user_accounts)}).")
            return

        LOGGER.info(f"Starting conversation simulation in group {group_id} with {len(user_accounts)} accounts.")
        clients = []
        for acc_name in user_accounts:
            session_str = self.session_manager.load_session_string(user_id, acc_name)
            proxy = self.account_proxies.get(f"{user_id}:{acc_name}")
            client = await self._create_worker_client(session_str, proxy)
            if client:
                try:
                    await client(InviteToChannelRequest(channel=group_id, users=[await client.get_me()]))
                    clients.append(client)
                    LOGGER.info(f"Account '{acc_name}' successfully joined group {group_id}.")
                    await asyncio.sleep(random.uniform(1, 3))
                except Exception as e:
                    LOGGER.error(f"Account '{acc_name}' failed to join group {group_id}: {e}")
                    if client.is_connected():
                        await client.disconnect()

        if len(clients) < 2:
            LOGGER.warning(f"Not enough clients successfully joined the group to simulate conversation.")
            for client in clients:
                if client.is_connected():
                    await client.disconnect()
            return

        try:
            chat_messages = await self._generate_persian_messages(user_id)
            if not chat_messages:
                LOGGER.warning("Failed to generate messages for conversation simulation.")
                return

            for i in range(10):
                sender_client = random.choice(clients)
                message_text = random.choice(chat_messages)
                try:
                    await sender_client.send_message(group_id, message_text)
                    me = await sender_client.get_me()
                    LOGGER.info(f"Account '{me.first_name}' sent message {i+1}/10 to group {group_id}.")
                except Exception as e:
                    LOGGER.error(f"Failed to send simulation message to {group_id}: {e}")
                await asyncio.sleep(random.uniform(10, 30))
        finally:
            LOGGER.info(f"Conversation simulation finished for group {group_id}. Disconnecting clients.")
            for client in clients:
                if client.is_connected():
                    await client.disconnect()

    # --- Main Worker Task ---
    async def run_group_creation_worker(self, user_id: int, account_name: str, user_client: TelegramClient) -> None:
        worker_key = f"{user_id}:{account_name}"
        try:
            async with self.worker_semaphore:
                LOGGER.info(f"Worker for {worker_key} started. Semaphore acquired.")
                avg_sleep = (Config.MIN_SLEEP_SECONDS + Config.MAX_SLEEP_SECONDS) / 2
                estimated_total_minutes = (Config.GROUPS_TO_CREATE * avg_sleep) / 60
                current_semester = self._get_group_count(worker_key)
                await self.bot.send_message(user_id, f"✅ **Operation for account `{account_name}` has started!**\n\n⏳ Estimated total time: ~{estimated_total_minutes:.0f} minutes.")

                for i in range(Config.GROUPS_TO_CREATE):
                    current_semester += 1
                    group_title = f"collage Semester {current_semester}"
                    group_description = f"Official group for semester {current_semester}."
                    try:
                        create_result = await self._send_request_with_reconnect(
                            user_client,
                            CreateChannelRequest(title=group_title, about=group_description, megagroup=True),
                            account_name
                        )
                        new_supergroup = create_result.chats[0]
                        LOGGER.info(f"Successfully created supergroup '{new_supergroup.title}' (ID: {new_supergroup.id}).")
                        group_id_str = str(new_supergroup.id)
                        self.created_groups[group_id_str] = {"owner_id": user_id, "last_simulated": 0}
                        self._save_created_groups()
                        await self._simulate_conversation(user_id, new_supergroup.id)
                        self._set_group_count(worker_key, current_semester)
                        groups_made = i + 1
                        groups_remaining = Config.GROUPS_TO_CREATE - groups_made
                        time_remaining_minutes = (groups_remaining * avg_sleep) / 60
                        progress_message = (
                            f"📊 [{account_name}] Group '{group_title}' created. ({groups_made}/{Config.GROUPS_TO_CREATE})\n"
                            f"⏳ Approx. time remaining: {time_remaining_minutes:.0f} minutes."
                        )
                        await self.bot.send_message(user_id, progress_message)
                        sleep_time = random.randint(Config.MIN_SLEEP_SECONDS, Config.MAX_SLEEP_SECONDS)
                        await asyncio.sleep(sleep_time)
                    except errors.AuthKeyUnregisteredError as e:
                        LOGGER.error(f"Auth key is unregistered for account '{account_name}'. Deleting session.")
                        sentry_sdk.capture_exception(e)
                        self.session_manager.delete_session_file(user_id, account_name)
                        self._remove_group_count(worker_key)
                        await self.bot.send_message(user_id, f"🚨 **Security Alert:** The session for account `{account_name}` was revoked. Operation stopped and account removed.")
                        break
                    except errors.UserRestrictedError as e:
                        LOGGER.error(f"Worker for {worker_key} failed: User is restricted.")
                        sentry_sdk.capture_exception(e)
                        await self.bot.send_message(user_id, f"❌ Account `{account_name}` is restricted and cannot create groups. Operation stopped.")
                        break
                    except errors.FloodWaitError as e:
                        LOGGER.warning(f"Flood wait error for {worker_key}. Sleeping for {e.seconds} seconds.")
                        sentry_sdk.capture_exception(e)
                        resume_time = datetime.now() + timedelta(seconds=e.seconds)
                        await self.bot.send_message(user_id, f"⏳ [{account_name}] Paused for {e.seconds / 60:.1f} minutes. Resuming at {resume_time:%H:%M:%S}.")
                        await asyncio.sleep(e.seconds)
                    except Exception as e:
                        LOGGER.error(f"Worker error for {worker_key}", exc_info=True)
                        sentry_sdk.capture_exception(e)
                        await self.bot.send_message(user_id, "❌ **Unexpected Error:** An issue occurred. Please check the logs and try again.")
                        break
        except asyncio.CancelledError:
            LOGGER.info(f"Task for {worker_key} was cancelled by the user.")
            await self.bot.send_message(user_id, f"⏹️ Operation for account `{account_name}` was stopped by you.")
        finally:
            LOGGER.info(f"Worker for {worker_key} finished.")
            if worker_key in self.active_workers:
                del self.active_workers[worker_key]
                self.active_workers_state.pop(worker_key, None)
                self._save_active_workers_state()
            if user_client and user_client.is_connected():
                await user_client.disconnect()

    async def on_login_success(self, event: events.NewMessage.Event, user_client: TelegramClient) -> None:
        user_id = event.sender_id
        account_name = self.user_sessions[user_id]['account_name']
        worker_key = f"{user_id}:{account_name}"
        self.session_manager.save_session_string(user_id, account_name, user_client.session.save())
        assigned_proxy = self.user_sessions[user_id].get('login_proxy')
        self.account_proxies[worker_key] = assigned_proxy
        self._save_account_proxies()
        if assigned_proxy:
            proxy_addr = f"{assigned_proxy['addr']}:{assigned_proxy['port']}"
            LOGGER.info(f"Login proxy {proxy_addr} assigned to account '{account_name}'.")
        else:
            LOGGER.info(f"Account '{account_name}' logged in directly and will run without a proxy.")
        if user_client and user_client.is_connected():
            await user_client.disconnect()
            LOGGER.info(f"Login client for user {user_id} ('{account_name}') disconnected successfully.")
        if 'client' in self.user_sessions[user_id]:
            del self.user_sessions[user_id]['client']
        if 'login_proxy' in self.user_sessions[user_id]:
            del self.user_sessions[user_id]['login_proxy']
        self.user_sessions[user_id]['state'] = 'authenticated'
        await self.bot.send_message(user_id, f"✅ Account `{account_name}` added successfully!")
        await self._send_accounts_menu(event)

    # --- Bot Event Handlers ---
    async def _start_handler(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        if user_id not in self.known_users and user_id != ADMIN_USER_ID:
            self.user_sessions[user_id] = {'state': 'awaiting_master_password'}
            await event.reply(Config.MSG_PROMPT_MASTER_PASSWORD, buttons=Button.clear())
        else:
            self.user_sessions[user_id] = {'state': 'authenticated'}
            await event.reply(Config.MSG_WELCOME, buttons=self._build_main_menu())
        raise events.StopPropagation

    async def _send_accounts_menu(self, event: events.NewMessage.Event) -> None:
        accounts_keyboard = self._build_accounts_menu(event.sender_id)
        await event.reply(Config.MSG_ACCOUNT_MENU_HEADER, buttons=accounts_keyboard)

    async def _manage_accounts_handler(self, event: events.NewMessage.Event) -> None:
        await self._send_accounts_menu(event)
        raise events.StopPropagation

    async def _server_status_handler(self, event: events.NewMessage.Event) -> None:
        active_count = len(self.active_workers)
        max_workers = Config.MAX_CONCURRENT_WORKERS
        status_text = f"**📊 Server Status**\n\n"
        status_text += f"**Active Workers:** {active_count} / {max_workers}\n"
        if active_count > 0:
            status_text += "\n**Accounts in Operation:**\n"
            for worker_key in self.active_workers.keys():
                _, acc_name = worker_key.split(":", 1)
                proxy_info = self.account_proxies.get(worker_key)
                proxy_str = f" (Proxy: {proxy_info['addr']})" if proxy_info else ""
                status_text += f"- `{acc_name}`{proxy_str}\n"
        else:
            status_text += "\nℹ️ No accounts are currently in operation."
        await event.reply(status_text, buttons=self._build_main_menu())
        raise events.StopPropagation

    async def _help_handler(self, event: events.NewMessage.Event) -> None:
        await event.reply(Config.MSG_HELP_TEXT, buttons=self._build_main_menu())
        raise events.StopPropagation

    async def _set_keywords_handler(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        self.user_sessions[user_id]['state'] = 'awaiting_keywords'
        await event.reply(Config.MSG_PROMPT_KEYWORDS, buttons=[[Button.text(Config.BTN_BACK)]])

    async def _admin_command_handler(self, event: events.NewMessage.Event, handler: callable):
        if event.sender_id != ADMIN_USER_ID:
            await event.reply("❌ You are not authorized to use this command.")
            return
        await handler(event)

    async def _debug_test_proxies_handler(self, event: events.NewMessage.Event) -> None:
        LOGGER.info(f"Admin {event.sender_id} initiated silent proxy test.")
        if not self.proxies:
            LOGGER.debug("Proxy test: No proxies found in file.")
            await self.bot.send_message(event.sender_id, "⚠️ No proxies found in the file to test.")
            return
        await self.bot.send_message(event.sender_id, "🧪 Starting silent proxy test... Results will be in system logs.")
        LOGGER.debug("--- PROXY TEST START ---")
        for proxy in self.proxies:
            # UPDATED: Log string for IP auth
            proxy_addr = f"{proxy['addr']}:{proxy['port']}"
            client = None
            try:
                device_params = random.choice([{'device_model': 'iPhone 14 Pro Max', 'system_version': '17.5.1'}, {'device_model': 'Samsung Galaxy S24 Ultra', 'system_version': 'SDK 34'}])
                LOGGER.debug(f"Testing proxy: {proxy['addr']} with device: {device_params}")
                client = TelegramClient(StringSession(), API_ID, API_HASH, proxy=proxy, timeout=Config.PROXY_TIMEOUT, **device_params)
                await client.connect()
                if client.is_connected():
                    LOGGER.info(f"  ✅ SUCCESS: {proxy_addr}")
            except Exception as e:
                LOGGER.warning(f"  ❌ FAILURE ({type(e).__name__}): {proxy_addr} - {e}")
            finally:
                if client and client.is_connected():
                    await client.disconnect()
        LOGGER.debug("--- DIRECT CONNECTION TEST ---")
        client = None
        try:
            device_params = random.choice([{'device_model': 'iPhone 14 Pro Max', 'system_version': '17.5.1'}, {'device_model': 'Samsung Galaxy S24 Ultra', 'system_version': 'SDK 34'}])
            LOGGER.debug(f"Testing direct connection with device: {device_params}")
            client = TelegramClient(StringSession(), API_ID, API_HASH, timeout=Config.PROXY_TIMEOUT, **device_params)
            await client.connect()
            if client.is_connected():
                LOGGER.info("  ✅ SUCCESS: Direct Connection")
        except Exception as e:
            LOGGER.warning(f"  ❌ FAILURE ({type(e).__name__}): Direct Connection - {e}")
        finally:
            if client and client.is_connected():
                await client.disconnect()
        LOGGER.info("Silent proxy test finished.")
        await self.bot.send_message(event.sender_id, "🏁 Silent proxy test finished. Check system logs for results.")
        raise events.StopPropagation

    async def _clean_sessions_handler(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        LOGGER.info(f"Admin {user_id} initiated session cleanup.")
        try:
            async with self.bot.conversation(user_id, timeout=30) as conv:
                await conv.send_message("⚠️ **WARNING:** This will delete all user sessions, counters, proxy assignments, and stop all running workers. Please confirm by sending `confirm` within 30 seconds.")
                response = await conv.get_response()
                if response.text.lower() != 'confirm':
                    await conv.send_message("❌ Operation cancelled.")
                    return
        except asyncio.TimeoutError:
            await self.bot.send_message(user_id, "❌ Confirmation timed out. Operation cancelled.")
            return
        msg = await self.bot.send_message(user_id, "🧹 Cleaning sessions and stopping workers...")
        stopped_workers = []
        if self.active_workers:
            LOGGER.info("Stopping all active workers before session cleanup.")
            for worker_key, task in list(self.active_workers.items()):
                task.cancel()
                stopped_workers.append(worker_key.split(":", 1)[1])
            self.active_workers.clear()
            await asyncio.sleep(1)
        report = ["**📝 Cleanup Report:**\n"]
        if stopped_workers:
            report.append(f"⏹️ **Stopped Workers:** {', '.join(f'`{name}`' for name in stopped_workers)}\n")
        deleted_files_count = 0
        if SESSIONS_DIR.exists():
            for item in SESSIONS_DIR.iterdir():
                if item.name != 'bot_session.session':
                    try:
                        if item.is_file():
                            item.unlink()
                            deleted_files_count += 1
                            LOGGER.debug(f"Deleted file: {item.name}")
                    except OSError as e:
                        LOGGER.error(f"Failed to delete file {item}: {e}")
        self.group_counts.clear()
        self.account_proxies.clear()
        self.known_users.clear()
        self.user_keywords.clear()
        self.pending_users.clear()
        self.created_groups.clear()
        self._save_user_keywords()
        self._save_pending_users()
        self._save_created_groups()
        report.append(f"🗑️ **Deleted Data Files:** {deleted_files_count} files\n")
        LOGGER.info(f"Deleted {deleted_files_count} data files from {SESSIONS_DIR}.")
        folders_to_clean = ["selenium_sessions", "api_sessions", "telethon_sessions"]
        for folder_name in folders_to_clean:
            folder_path = Path(folder_name)
            if folder_path.exists() and folder_path.is_dir():
                try:
                    shutil.rmtree(folder_path)
                    report.append(f"📁 **Deleted Folder:** `{folder_name}`\n")
                    LOGGER.info(f"Deleted folder: {folder_name}")
                except OSError as e:
                    LOGGER.error(f"Failed to delete folder {folder_path}: {e}")
        report.append("\n✅ Cleanup completed successfully.")
        await msg.edit(''.join(report))
        raise events.StopPropagation

    async def _test_sentry_handler(self, event: events.NewMessage.Event) -> None:
        LOGGER.info(f"Admin {event.sender_id} initiated Sentry test.")
        await event.reply("🧪 Sending a test exception to Sentry. Please check your Sentry dashboard.")
        try:
            1 / 0
        except Exception as e:
            sentry_sdk.capture_exception(e)
            await event.reply("✅ Test exception sent to Sentry!")

    async def _initiate_login_flow(self, event: events.NewMessage.Event) -> None:
        self.user_sessions[event.sender_id] = {'state': 'awaiting_phone'}
        await event.reply('📞 Please send the phone number for the new account in international format (e.g., `+15551234567`).', buttons=Button.clear())

    async def _initiate_selenium_login_flow(self, event: events.NewMessage.Event) -> None:
        await event.reply(Config.MSG_BROWSER_RUNNING)
        await asyncio.sleep(2)
        await self._initiate_login_flow(event)

    async def _message_router(self, event: events.NewMessage.Event) -> None:
        if not isinstance(getattr(event, 'message', None), Message) or not event.message.text:
            return
        text = event.message.text
        user_id = event.sender_id
        if user_id not in self.known_users and user_id != ADMIN_USER_ID:
            if user_id in self.pending_users:
                await event.reply(Config.MSG_AWAITING_APPROVAL)
                return
            await self._handle_master_password(event)
            return
        session = self.user_sessions.get(user_id, {})
        state = session.get('state')
        if state == 'awaiting_keywords':
            await self._handle_keywords_input(event)
            return
        login_flow_states = ['awaiting_phone', 'awaiting_code', 'awaiting_password', 'awaiting_account_name']
        if state in login_flow_states:
            if text == Config.BTN_BACK:
                self.user_sessions[user_id]['state'] = 'authenticated'
                await self._send_accounts_menu(event)
                return
            state_map = {
                'awaiting_phone': self._handle_phone_input,
                'awaiting_code': self._handle_code_input,
                'awaiting_password': self._handle_password_input,
                'awaiting_account_name': self._handle_account_name_input
            }
            await state_map[state](event)
            return
        if state != 'authenticated':
            await self._start_handler(event)
            return
        admin_routes = {
            "/debug_proxies": self._debug_test_proxies_handler,
            "/clean_sessions": self._clean_sessions_handler,
            "/test_sentry": self._test_sentry_handler,
        }
        if text in admin_routes:
            await self._admin_command_handler(event, admin_routes[text])
            return
        route_map = {
            Config.BTN_MANAGE_ACCOUNTS: self._manage_accounts_handler,
            Config.BTN_HELP: self._help_handler,
            Config.BTN_BACK: self._start_handler,
            Config.BTN_ADD_ACCOUNT: self._initiate_login_flow,
            Config.BTN_ADD_ACCOUNT_SELENIUM: self._initiate_selenium_login_flow,
            Config.BTN_SERVER_STATUS: self._server_status_handler,
            Config.BTN_SET_KEYWORDS: self._set_keywords_handler,
        }
        handler = route_map.get(text)
        if handler:
            await handler(event)
            return
        start_match = re.match(rf"{re.escape(Config.BTN_START_PREFIX)} (.*)", text)
        if start_match:
            await self._start_process_handler(event, start_match.group(1))
            return
        stop_match = re.match(rf"{re.escape(Config.BTN_STOP_PREFIX)} (.*)", text)
        if stop_match:
            await self._cancel_worker_handler(event, stop_match.group(1))
            return
        delete_match = re.match(rf"{re.escape(Config.BTN_DELETE_PREFIX)} (.*)", text)
        if delete_match:
            await self._delete_account_handler(event, delete_match.group(1))
            return

    async def _start_process_handler(self, event: events.NewMessage.Event, account_name: str) -> None:
        user_id = event.sender_id
        worker_key = f"{user_id}:{account_name}"
        if worker_key in self.active_workers:
            await event.reply('⏳ An operation for this account is already in progress.')
            return
        session_str = self.session_manager.load_session_string(user_id, account_name)
        if not session_str:
            await event.reply('❌ No session found for this account. Please delete and add it again.')
            return
        await event.reply(f'🚀 Preparing to start operation for account `{account_name}`...')
        user_client = None
        try:
            assigned_proxy = self.account_proxies.get(worker_key)
            user_client = await self._create_worker_client(session_str, assigned_proxy)
            if not user_client:
                await event.reply(f'❌ Failed to connect to Telegram for account `{account_name}` using its assigned proxy.')
                return
            if await user_client.is_user_authorized():
                task = asyncio.create_task(self.run_group_creation_worker(user_id, account_name, user_client))
                self.active_workers[worker_key] = task
                self.active_workers_state[worker_key] = {"user_id": user_id, "account_name": account_name}
                self._save_active_workers_state()
                await self._send_accounts_menu(event)
            else:
                self.session_manager.delete_session_file(user_id, account_name)
                self._remove_group_count(worker_key)
                await event.reply(f'⚠️ The session for account `{account_name}` has expired and was deleted. Please add it again.')
        except errors.AuthKeyUnregisteredError as e:
            LOGGER.error(f"Auth key is unregistered for account '{account_name}'. Deleting session.")
            sentry_sdk.capture_exception(e)
            self.session_manager.delete_session_file(user_id, account_name)
            self._remove_group_count(worker_key)
            await event.reply(f"🚨 **Security Alert:** The session for account `{account_name}` was revoked by Telegram, likely due to concurrent use. The account has been removed. Please add it again.")
            await self._send_accounts_menu(event)
        except Exception as e:
            LOGGER.error(f"Error starting process for {worker_key}", exc_info=True)
            sentry_sdk.capture_exception(e)
            await event.reply(f'❌ An error occurred while connecting to account `{account_name}`.')
        finally:
            if user_client and not self.active_workers.get(worker_key):
                if user_client.is_connected():
                    await user_client.disconnect()

    async def _cancel_worker_handler(self, event: events.NewMessage.Event, account_name: str) -> None:
        user_id = event.sender_id
        worker_key = f"{user_id}:{account_name}"
        if worker_key in self.active_workers:
            task = self.active_workers[worker_key]
            task.cancel()
            LOGGER.info(f"User initiated cancellation for worker {worker_key}.")
            try:
                await task
            except asyncio.CancelledError:
                LOGGER.info(f"Worker task {worker_key} successfully cancelled and cleaned up.")
            await self._send_accounts_menu(event)
        else:
            await event.reply(f"ℹ️ No active operation to stop for account `{account_name}`.")

    async def _delete_account_handler(self, event: events.NewMessage.Event, account_name: str) -> None:
        user_id = event.sender_id
        worker_key = f"{user_id}:{account_name}"
        if worker_key in self.active_workers:
            self.active_workers[worker_key].cancel()
            LOGGER.info(f"Worker for {worker_key} cancelled due to account deletion.")
        if self.session_manager.delete_session_file(user_id, account_name):
            self._remove_group_count(worker_key)
            if worker_key in self.account_proxies:
                del self.account_proxies[worker_key]
                self._save_account_proxies()
            await event.reply(f"✅ Account `{account_name}` deleted successfully and any related operation was stopped.")
        else:
            await event.reply(f"✅ Operation for account `{account_name}` stopped (session did not exist).")
        await self._send_accounts_menu(event)

    # --- Login Flow Handlers ---
    async def _handle_master_password(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        if user_id == ADMIN_USER_ID:
            self.user_sessions[user_id] = {'state': 'authenticated'}
            if user_id not in self.known_users:
                self.known_users.append(user_id)
                self._save_known_users()
            await event.reply(Config.MSG_WELCOME, buttons=self._build_main_menu())
            return
        hashed_input = hashlib.sha256(event.message.text.strip().encode()).hexdigest()
        if hashed_input == MASTER_PASSWORD_HASH:
            if user_id not in self.pending_users:
                self.pending_users.append(user_id)
                self._save_pending_users()
                approval_buttons = [[Button.inline("✅ Approve", f"approve_{user_id}"), Button.inline("❌ Deny", f"deny_{user_id}")]]
                await self.bot.send_message(ADMIN_USER_ID, f"🔔 New user access request from ID: `{user_id}`", buttons=approval_buttons)
            await event.reply(Config.MSG_AWAITING_APPROVAL)
        else:
            await event.reply(Config.MSG_INCORRECT_MASTER_PASSWORD)
        raise events.StopPropagation

    async def _handle_keywords_input(self, event: events.NewMessage.Event) -> None:
        user_id = str(event.sender_id)
        keywords_text = event.message.text.strip()
        if keywords_text:
            keywords = [kw.strip() for kw in keywords_text.split(',')]
            self.user_keywords[user_id] = keywords
            self._save_user_keywords()
            await event.reply(Config.MSG_KEYWORDS_SET, buttons=self._build_main_menu())
        else:
            await event.reply("❌ ورودی نامعتبر است. لطفاً حداقل یک کلمه کلیدی وارد کنید.", buttons=[[Button.text(Config.BTN_BACK)]])
        self.user_sessions[event.sender_id]['state'] = 'authenticated'
        raise events.StopPropagation

    async def _handle_phone_input(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        phone_number = event.message.text.strip()
        if not re.match(r'^\+\d{10,}$', phone_number):
            await event.reply(
                '❌ **Invalid phone number format.**\n'
                'Please enter the full number in international format (e.g., `+15551234567`).',
                buttons=[[Button.text(Config.BTN_BACK)]]
            )
            return
        self.user_sessions[user_id]['phone'] = phone_number
        selected_proxy = self._get_available_proxy()
        self.user_sessions[user_id]['login_proxy'] = selected_proxy
        user_client = None
        try:
            user_client = await self._create_login_client(selected_proxy)
            if not user_client:
                proxy_msg = f" with proxy {selected_proxy['addr']}:{selected_proxy['port']}" if selected_proxy else " directly"
                await event.reply(f'❌ Failed to connect to Telegram{proxy_msg}. Please try again later.')
                return
            self.user_sessions[user_id]['client'] = user_client
            sent_code = await user_client.send_code_request(self.user_sessions[user_id]['phone'])
            self.user_sessions[user_id]['phone_code_hash'] = sent_code.phone_code_hash
            self.user_sessions[user_id]['state'] = 'awaiting_code'
            await event.reply('💬 A login code has been sent. Please send it here.', buttons=[[Button.text(Config.BTN_BACK)]])
        except Exception as e:
            LOGGER.error(f"Phone input error for {user_id}", exc_info=True)
            sentry_sdk.capture_exception(e)
            self.user_sessions[user_id]['state'] = 'awaiting_phone'
            await event.reply(
                '❌ **Error:** Invalid phone number or issue sending code. Please try again with the international format (+countrycode) or cancel.',
                buttons=[[Button.text(Config.BTN_BACK)]]
            )
        finally:
            if user_client and self.user_sessions.get(user_id, {}).get('state') != 'awaiting_code':
                 if user_client.is_connected():
                    await user_client.disconnect()

    async def _handle_code_input(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        user_client = self.user_sessions[user_id]['client']
        try:
            await user_client.sign_in(self.user_sessions[user_id]['phone'], code=event.message.text.strip(), phone_code_hash=self.user_sessions[user_id].get('phone_code_hash'))
            self.user_sessions[user_id]['state'] = 'awaiting_account_name'
            await event.reply('✅ Login successful! Please enter a nickname for this account (e.g., `Main Account` or `Second Number`).', buttons=[[Button.text(Config.BTN_BACK)]])
        except errors.SessionPasswordNeededError:
            self.user_sessions[user_id]['state'] = 'awaiting_password'
            await event.reply('🔑 This account has two-step verification enabled. Please send the password.', buttons=[[Button.text(Config.BTN_BACK)]])
        except errors.PhoneCodeExpiredError:
            try:
                LOGGER.warning(f"Phone code for {user_id} expired. Requesting new code.")
                sent_code = await user_client.send_code_request(self.user_sessions[user_id]['phone'])
                self.user_sessions[user_id]['phone_code_hash'] = sent_code.phone_code_hash
                self.user_sessions[user_id]['state'] = 'awaiting_code'
                await event.reply('⚠️ The code expired. A new code has been sent. Please enter the new code.', buttons=[[Button.text(Config.BTN_BACK)]])
            except Exception as e:
                LOGGER.error(f"Failed to resend code for {user_id} after expiration: {e}", exc_info=True)
                sentry_sdk.capture_exception(e)
                self.user_sessions[user_id]['state'] = 'awaiting_phone'
                await event.reply('❌ **Error:** The previous code expired and resending failed. Please enter the phone number again.', buttons=[[Button.text(Config.BTN_BACK)]])
        except Exception as e:
            LOGGER.error(f"Code input error for {user_id}", exc_info=True)
            sentry_sdk.capture_exception(e)
            self.user_sessions[user_id]['state'] = 'awaiting_phone'
            await event.reply('❌ **Error:** The code is invalid. Please enter the phone number again.', buttons=[[Button.text(Config.BTN_BACK)]])

    async def _handle_password_input(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        try:
            await self.user_sessions[user_id]['client'].sign_in(password=event.message.text.strip())
            self.user_sessions[user_id]['state'] = 'awaiting_account_name'
            await event.reply('✅ Login successful! Please enter a nickname for this account (e.g., `Main Account` or `Second Number`).', buttons=[[Button.text(Config.BTN_BACK)]])
        except Exception as e:
            LOGGER.error(f"Password input error for {user_id}", exc_info=True)
            sentry_sdk.capture_exception(e)
            self.user_sessions[user_id]['state'] = 'awaiting_password'
            await event.reply('❌ **Error:** Incorrect password. Please try again.', buttons=[[Button.text(Config.BTN_BACK)]])

    async def _handle_account_name_input(self, event: events.NewMessage.Event) -> None:
        user_id = event.sender_id
        account_name = event.message.text.strip()
        if not account_name:
            await event.reply("❌ Nickname cannot be empty. Please enter a name.", buttons=[[Button.text(Config.BTN_BACK)]])
            return
        if account_name in self.session_manager.get_user_accounts(user_id):
            await event.reply(f"❌ You already have an account with the nickname `{account_name}`. Please choose another name.", buttons=[[Button.text(Config.BTN_BACK)]])
            return
        self.user_sessions[user_id]['account_name'] = account_name
        user_client = self.user_sessions[user_id]['client']
        await self.on_login_success(event, user_client)

    async def _approval_handler(self, event: events.CallbackQuery.Event):
        if event.sender_id != ADMIN_USER_ID:
            await event.answer("You are not authorized to perform this action.")
            return
        data = event.data.decode('utf-8')
        action, user_id_str = data.split('_')
        user_id = int(user_id_str)
        if action == "approve":
            if user_id in self.pending_users:
                self.pending_users.remove(user_id)
                self.known_users.append(user_id)
                self._save_pending_users()
                self._save_known_users()
                await event.edit(f"✅ User `{user_id}` has been approved.")
                await self.bot.send_message(user_id, Config.MSG_USER_APPROVED)
                LOGGER.info(f"Admin approved user {user_id}.")
            else:
                await event.edit(f"⚠️ User `{user_id}` was not found in the pending list.")
        elif action == "deny":
            if user_id in self.pending_users:
                self.pending_users.remove(user_id)
                self._save_pending_users()
                await event.edit(f"❌ User `{user_id}` has been denied.")
                await self.bot.send_message(user_id, Config.MSG_USER_DENIED)
                LOGGER.info(f"Admin denied user {user_id}.")
            else:
                await event.edit(f"⚠️ User `{user_id}` was not found in the pending list.")

    async def _daily_conversation_scheduler(self):
        while True:
            await asyncio.sleep(3600)
            now_ts = datetime.now().timestamp()
            groups_to_simulate = []
            for group_id, data in self.created_groups.items():
                last_simulated_ts = data.get("last_simulated", 0)
                if (now_ts - last_simulated_ts) > 86400:
                    groups_to_simulate.append((int(group_id), data["owner_id"]))
            if not groups_to_simulate:
                continue
            LOGGER.info(f"Daily scheduler found {len(groups_to_simulate)} groups needing conversation simulation.")
            for group_id, owner_id in groups_to_simulate:
                asyncio.create_task(self._simulate_conversation(owner_id, group_id))
                self.created_groups[str(group_id)]["last_simulated"] = now_ts
                await asyncio.sleep(5)
            self._save_created_groups()

    # --- Main Run Method ---
    def register_handlers(self) -> None:
        self.bot.add_event_handler(self._start_handler, events.NewMessage(pattern='/start'))
        self.bot.add_event_handler(self._message_router, events.NewMessage)
        self.bot.add_event_handler(self._approval_handler, events.CallbackQuery)

    async def run(self) -> None:
        self.register_handlers()
        LOGGER.info("Starting bot...")
        try:
            await self.bot.start(bot_token=BOT_TOKEN)
            LOGGER.info("Bot service started successfully.")
            self.bot.loop.create_task(self._daily_conversation_scheduler())
            for worker_key, worker_data in self.active_workers_state.items():
                user_id = worker_data["user_id"]
                account_name = worker_data["account_name"]
                LOGGER.info(f"Resuming worker for account '{account_name}' after restart.")
                try:
                    await self.bot.send_message(
                        user_id,
                        f"⚠️ The bot has restarted. Please manually start the process again for account `{account_name}` from the 'Manage Accounts' menu."
                    )
                except Exception:
                    pass
            if self.known_users:
                await self._broadcast_message("✅ Bot has started successfully and is now online.")
            await self.bot.run_until_disconnected()
        finally:
            LOGGER.info("Bot service is shutting down. Disconnecting main bot client.")
            if self.bot.is_connected():
                await self.bot.disconnect()


if __name__ == "__main__":
    bot_instance = GroupCreatorBot(SessionManager)
    asyncio.run(bot_instance.run())
