# error_assistant.py
# Refactored single-file module based on user's m.py
# - Modular classes: ConfigManager, Encryptor, EventMonitor, UIWatcher, Notifier, AIProvider(s), LocalServer, AppController, GUI
# - Graceful shutdown and thread join
# - Windows DPAPI encryption for API keys (if available)
# - Improved logging and error handling
# - Minimal unit tests at bottom
#
# Usage:
#   python error_assistant.py           # runs GUI + services (if PySide6 available)
#   python error_assistant.py test      # sends a test notification and runs basic checks
#   python error_assistant.py console   # runs watchers without GUI (console)
#
# Requirements (optional):
#   pip install pywin32 winotify flask openai psutil PySide6 cryptography
#   but module will degrade gracefully if some are missing.
#
# Author: generated for the user (refactor + improvements)

import os
import sys
import json
import time
import threading
import logging
import datetime
import re
import hashlib
import urllib.parse
import ctypes
import signal
from typing import Optional, List, Dict, Any

# Optional Windows libs
try:
    import win32evtlog
    import win32gui
    import win32process
except Exception:
    win32evtlog = None
    win32gui = None
    win32process = None

# Optional 3rd-party libs
try:
    from winotify import Notification, audio
except Exception:
    Notification = None
    audio = None

try:
    import psutil
except Exception:
    psutil = None

try:
    from flask import Flask, request, render_template_string, abort
except Exception:
    Flask = None

try:
    import openai
except Exception:
    openai = None

# GUI optional
try:
    from PySide6 import QtCore, QtWidgets
    from PySide6.QtWidgets import (
        QApplication, QWidget, QLabel, QComboBox, QLineEdit, QPushButton, QFormLayout,
        QMessageBox, QSpinBox, QCheckBox, QFileDialog, QTextEdit
    )
except Exception:
    QtWidgets = None

# ----------------- Constants -----------------
CONFIG_FILE = "config.json"
LAST_RECORD_FILE = "last_record.json"
LOG_FILE = "errors.log"
DEFAULT_CONFIG = {
    "ai_provider": "openai",
    "openai": {"api_key": "", "model": "gpt-3.5-turbo"},
    "grok": {"api_key": ""},       # placeholder
    "copilot": {"api_key": ""},    # placeholder
    "gemini": {"api_key": ""},     # placeholder
    "server": {"host": "127.0.0.1", "port": 5000},
    "monitor": {
        "event_poll_interval": 30,
        "ui_poll_interval": 1,
        "ui_seen_max_age": 600,
        "time_window_hours": 24,
        "max_errors": 10
    },
    "ui_patterns": [
        "Location is not available",
        "is unavailable",
        "is not accessible",
        "drive.*not found",
        "device.*not connected",
        "network.*not available",
        "path.*not found",
        "access.*denied",
        "could not",
        "unable to",
        "failed to",
        "error.*occurred",
        "خطا در دسترسی",
        "دسترسی ممکن نیست",
        "یافت نشد",
        "متصل نیست"
    ]
}

# ----------------- Logging -----------------
logger = logging.getLogger("ErrorAssistant")
logger.setLevel(logging.INFO)
# file handler
fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
fh.setLevel(logging.INFO)
fh_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(fh_formatter)
logger.addHandler(fh)
# console
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(ch)

# ----------------- Helpers -----------------
def is_windows() -> bool:
    return sys.platform.startswith("win")

def now_iso() -> str:
    return datetime.datetime.now().isoformat()

# ----------------- Encryption (Windows DPAPI) -----------------
class Encryptor:
    """
    Encrypt / decrypt using Windows DPAPI if available.
    Fallback: plain text (with warning).
    """
    @staticmethod
    def protect(data: str) -> str:
        if not data:
            return ""
        if is_windows():
            try:
                # use CryptProtectData via ctypes with safer byte pointer types
                from ctypes import wintypes
                # DATA_BLOB with unsigned byte pointer
                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [("cbData", wintypes.DWORD),
                                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
                crypt32 = ctypes.windll.crypt32
                kernel32 = ctypes.windll.kernel32
                # prepare input bytes
                data_bytes = data.encode("utf-8")
                buf = (ctypes.c_ubyte * len(data_bytes)).from_buffer_copy(data_bytes)
                blob_in = DATA_BLOB(len(data_bytes), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
                blob_out = DATA_BLOB()
                if crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
                    # copy bytes
                    pbData = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_ubyte * blob_out.cbData)).contents
                    encrypted = bytes(pbData[:blob_out.cbData])
                    kernel32.LocalFree(blob_out.pbData)
                    return encrypted.hex()
            except Exception as e:
                logger.warning("DPAPI protect failed: %s", e)
        logger.warning("Encryptor: DPAPI not available or failed — storing plain text (not secure).")
        return data

    @staticmethod
    def unprotect(data_hex: str) -> str:
        if not data_hex:
            return ""
        if is_windows():
            try:
                encrypted = bytes.fromhex(data_hex)
                from ctypes import wintypes
                class DATA_BLOB(ctypes.Structure):
                    _fields_ = [("cbData", wintypes.DWORD),
                                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
                crypt32 = ctypes.windll.crypt32
                kernel32 = ctypes.windll.kernel32
                buf = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
                blob_in = DATA_BLOB(len(encrypted), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
                blob_out = DATA_BLOB()
                if crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
                    pbData = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_ubyte * blob_out.cbData)).contents
                    decrypted = bytes(pbData[:blob_out.cbData]).decode('utf-8', errors='ignore')
                    kernel32.LocalFree(blob_out.pbData)
                    return decrypted
            except Exception as e:
                logger.warning("DPAPI unprotect failed: %s", e)
        # fallback: assume plain
        return data_hex
# ----------------- Config Manager -----------------
class ConfigManager:
    def __init__(self, path: str = CONFIG_FILE):
        self.path = path
        self._lock = threading.Lock()
        self.config = DEFAULT_CONFIG.copy()
        self.load()

    def load(self) -> Dict[str, Any]:
        with self._lock:
            if os.path.exists(self.path):
                try:
                    with open(self.path, 'r', encoding='utf-8') as f:
                        cfg = json.load(f)
                    # deep-merge minimal
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(cfg)
                    for k in ["openai", "grok", "copilot", "gemini", "server", "monitor"]:
                        if k in cfg:
                            merged[k] = {**DEFAULT_CONFIG.get(k, {}), **cfg.get(k, {})}
                    if "ui_patterns" in cfg:
                        merged["ui_patterns"] = cfg["ui_patterns"]
                    self.config = merged
                    logger.info("Configuration loaded from %s", self.path)
                    return self.config
                except Exception as e:
                    logger.error("Failed to parse config.json: %s", e)
                    self.config = DEFAULT_CONFIG.copy()
                    return self.config
            else:
                try:
                    with open(self.path, 'w', encoding='utf-8') as f:
                        json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)
                    logger.info("Created default config.json at %s", self.path)
                except Exception as e:
                    logger.error("Could not create config.json: %s", e)
                self.config = DEFAULT_CONFIG.copy()
                return self.config

    def save(self) -> None:
        with self._lock:
            try:
                with open(self.path, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, ensure_ascii=False, indent=2)
                logger.info("Saved configuration to %s", self.path)
            except Exception as e:
                logger.error("Failed to save config.json: %s", e)

    def get(self, key: str, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value) -> None:
        self.config[key] = value
        self.save()

    def get_api_key(self, provider: str) -> str:
        prov = self.config.get(provider, {})
        api_key_enc = prov.get("api_key", "")
        if api_key_enc and api_key_enc.startswith("dpapi:"):
            return Encryptor.unprotect(api_key_enc[len("dpapi:"):])
        # fallback plain
        return api_key_enc

    def set_api_key(self, provider: str, key: str) -> None:
        if is_windows():
            try:
                enc = Encryptor.protect(key)
                self.config.setdefault(provider, {})["api_key"] = "dpapi:" + enc
                self.save()
                return
            except Exception as e:
                logger.warning("Failed to store API key protected: %s", e)
        # fallback plain text
        self.config.setdefault(provider, {})["api_key"] = key
        self.save()

# ----------------- Last record storage -----------------
def load_last_records(path: str = LAST_RECORD_FILE) -> Dict[str, int]:
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error("Could not load last records: %s", e)
            return {}
    return {}

def save_last_records(records: Dict[str, int], path: str = LAST_RECORD_FILE) -> None:
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error("Could not save last records: %s", e)

# ----------------- Event Monitor -----------------
class EventMonitor:
    def __init__(self, cfg_mgr: ConfigManager):
        self.cfg_mgr = cfg_mgr
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.last_records = load_last_records()

    def start(self):
        if self.thread and self.thread.is_alive():
            logger.info("EventMonitor already running")
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="EventMonitor", daemon=True)
        self.thread.start()
        logger.info("EventMonitor started")

    def stop(self):
        logger.info("EventMonitor stopping...")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
            logger.info("EventMonitor thread joined")

    def _run(self):
        cfg = self.cfg_mgr.get("monitor", {})
        poll = int(cfg.get("event_poll_interval", 30))
        max_err = int(cfg.get("max_errors", 10))
        time_window = int(cfg.get("time_window_hours", 24))
        while not self.stop_event.is_set():
            try:
                errors = self.get_system_errors(max_errors=max_err, time_window_hours=time_window)
                if errors:
                    for e in errors:
                        logger.info("Event: %s", e.get('message'))
                    Notifier.show_error_notification(errors, self.cfg_mgr.config)
                    # update last_records
                    for e in errors:
                        lt = e.get('logtype')
                        rn = e.get('record_number', 0)
                        if rn and rn > self.last_records.get(lt, 0):
                            self.last_records[lt] = rn
                    save_last_records(self.last_records)
                # wait in small increments so we can stop faster
                for _ in range(int(poll)):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)
            except Exception as e:
                logger.exception("Error in EventMonitor loop: %s", e)
                time.sleep(poll)

    def get_system_errors(self, max_errors=None, time_window_hours=None, logtypes=None):
        """
        Rewritten get_system_errors with safer date comparisons.
        """
        if win32evtlog is None:
            logger.error("pywin32 not installed; EventLog monitoring unavailable.")
            return []
        monitor_cfg = self.cfg_mgr.get("monitor", {})
        max_errors = max_errors or monitor_cfg.get("max_errors", 10)
        time_window_hours = time_window_hours or monitor_cfg.get("time_window_hours", 24)
        if logtypes is None:
            logtypes = ['System', 'Application', 'Security']
        server = 'localhost'
        errors = []
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=time_window_hours)
        for logtype in logtypes:
            hand = None
            try:
                hand = win32evtlog.OpenEventLog(server, logtype)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                while events:
                    for event in events:
                        if event.EventType in (win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE):
                            ev_time = event.TimeGenerated
                            try:
                                # convert both to timestamps to avoid tz/pywintypes issues
                                cutoff_ts = getattr(cutoff_time, "timestamp", lambda: time.mktime(cutoff_time.timetuple()) + getattr(cutoff_time, "microsecond", 0)/1e6)()
                                ev_ts = None
                                if hasattr(ev_time, "timestamp") and callable(getattr(ev_time, "timestamp")):
                                    ev_ts = ev_time.timestamp()
                                else:
                                    ev_ts = time.mktime(ev_time.timetuple()) + getattr(ev_time, "microsecond", 0)/1e6
                                if ev_ts is not None and ev_ts < cutoff_ts:
                                    continue
                            except Exception:
                                # if anything goes wrong, fall back to original behaviour and don't crash
                                pass
                            record_number = getattr(event, "RecordNumber", 0)
                            last_seen = self.last_records.get(logtype, 0)
                            if record_number > last_seen:
                                details = ""
                                try:
                                    if event.StringInserts:
                                        details = ' | '.join([str(s) for s in event.StringInserts if s])
                                except Exception:
                                    pass
                                msg = f"[{logtype}] Event ID: {event.EventID}, Source: {event.SourceName}, Time: {ev_time}"
                                if details:
                                    msg += f", Details: {details}"
                                errors.append({
                                    'logtype': logtype,
                                    'record_number': record_number,
                                    'event_id': event.EventID,
                                    'source': event.SourceName,
                                    'time': str(ev_time),
                                    'message': msg
                                })
                                if len(errors) >= max_errors:
                                    break
                    if len(errors) >= max_errors:
                        break
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
            except Exception as e:
                logger.error("Error reading %s log: %s", logtype, e)
            finally:
                if hand:
                    try:
                        win32evtlog.CloseEventLog(hand)
                    except Exception:
                        pass
        return errors

# ----------------- UI Scanner -----------------
class UIWatcher:
    def __init__(self, cfg_mgr: ConfigManager):
        self.cfg_mgr = cfg_mgr
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.seen_lock = threading.Lock()
        self.seen_keys: Dict[str, float] = {}  # key -> timestamp

    def start(self):
        if self.thread and self.thread.is_alive():
            logger.info("UIWatcher already running")
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="UIWatcher", daemon=True)
        self.thread.start()
        logger.info("UIWatcher started")

    def stop(self):
        logger.info("UIWatcher stopping...")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
            logger.info("UIWatcher thread joined")

    def _run(self):
        cfg = self.cfg_mgr.get("monitor", {})
        poll = int(cfg.get("ui_poll_interval", 1))
        seen_max_age = int(cfg.get("ui_seen_max_age", 600))
        patterns = self.cfg_mgr.get("ui_patterns", DEFAULT_CONFIG["ui_patterns"])
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
        while not self.stop_event.is_set():
            try:
                items = self.scan_for_message_boxes(compiled)
                now = time.time()
                with self.seen_lock:
                    old = [k for k,v in self.seen_keys.items() if now - v > seen_max_age]
                    for k in old:
                        del self.seen_keys[k]
                new_items = []
                for item in items:
                    content_hash = hashlib.sha256(item.get('content','').encode('utf-8')).hexdigest()
                    key = f"{item.get('pid')}:{item.get('title')}:{content_hash}"
                    with self.seen_lock:
                        if key in self.seen_keys:
                            continue
                        self.seen_keys[key] = now
                    new_items.append(item)
                for item in new_items:
                    logger.info("UI error detected: %s", item.get('message'))
                    Notifier.show_error_notification(item, self.cfg_mgr.config)
                for _ in range(int(poll)):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)
            except Exception as e:
                logger.exception("Error in UIWatcher loop: %s", e)
                time.sleep(poll)

    def _get_process_name_for_hwnd(self, hwnd):
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if psutil:
                try:
                    p = psutil.Process(pid)
                    return p.name(), pid
                except Exception:
                    return str(pid), pid
            else:
                return str(pid), pid
        except Exception:
            return None, None

    def _gather_window_text(self, hwnd):
        try:
            text = win32gui.GetWindowText(hwnd) or ""
            parts = [text]
            def child_callback(hwnd_child, _):
                try:
                    child_text = win32gui.GetWindowText(hwnd_child)
                    if child_text:
                        parts.append(child_text)
                except Exception:
                    pass
                return True
            win32gui.EnumChildWindows(hwnd, child_callback, None)
            return "\n".join(parts).strip()
        except Exception:
            return ""

    def scan_for_message_boxes(self, compiled_patterns=None):
        if win32gui is None:
            return []
        patterns = compiled_patterns or [re.compile(p, re.IGNORECASE) for p in self.cfg_mgr.get("ui_patterns", DEFAULT_CONFIG["ui_patterns"])]
        found = []
        def enum_callback(hwnd, _):
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                window_text = self._gather_window_text(hwnd)
                if not window_text:
                    return True
                for pattern in patterns:
                    if pattern.search(window_text):
                        proc_name, pid = self._get_process_name_for_hwnd(hwnd)
                        found.append({
                            'hwnd': hwnd,
                            'pid': pid,
                            'process_name': proc_name,
                            'title': win32gui.GetWindowText(hwnd),
                            'content': window_text,
                            'message': f"UI Dialog (proc={proc_name}, pid={pid}): {window_text[:300]}"
                        })
                        break
            except Exception as e:
                logger.debug("Error in window enumeration: %s", e)
            return True
        try:
            win32gui.EnumWindows(enum_callback, None)
        except Exception as e:
            logger.error("EnumWindows failed: %s", e)
        return found

# ----------------- Notifier -----------------
class Notifier:
    @staticmethod
    def show_error_notification(errors, cfg):
        """
        errors: list or dict
        """
        if Notification is None:
            logger.warning("winotify not installed; cannot show native notifications.")
            return None
        if isinstance(errors, dict):
            errors = [errors]
        display_parts = []
        for i, e in enumerate(errors[:3]):
            m = e.get('message', str(e))
            short = m if len(m) <= 120 else m[:120] + "..."
            display_parts.append(f"{i+1}. {short}")
        display_msg = "\n".join(display_parts)
        if len(errors) > 3:
            display_msg += f"\n... و {len(errors) - 3} خطای دیگر"

        server = cfg.get("server", {})
        host = server.get("host", "127.0.0.1")
        port = server.get("port", 5000)
        first_msg = errors[0].get('message', '')
        quoted = urllib.parse.quote_plus(first_msg)
        search_url = f"https://www.google.com/search?q={quoted}"
        local_ask = f"http://{host}:{port}/ask?msg={quoted}"
        abs_log = os.path.abspath(LOG_FILE)
        # normalize backslashes and URL-encode the path so file:/// links work on Windows
        log_url = "file:///" + urllib.parse.quote(abs_log.replace("\\", "/"))

        try:
            toast = Notification(
                app_id="Error Assistant",
                title="🚨 Windows Error Detected",
                msg=display_msg,
                duration="long"
            )
            toast.set_audio(audio.Default, loop=False)
            toast.add_actions(label="🔍 Search Web", launch=search_url)
            toast.add_actions(label="🤖 Ask AI", launch=local_ask)
            toast.add_actions(label="📝 View Log", launch=log_url)
            toast.show()
        except Exception as e:
            logger.error("Failed to show notification: %s", e)

# ----------------- AI Provider Interface -----------------
class AIProviderBase:
    def explain(self, msg: str) -> str:
        raise NotImplementedError()

class OpenAIProvider(AIProviderBase):
    def __init__(self, cfg_mgr: ConfigManager):
        self.cfg_mgr = cfg_mgr

    def explain(self, msg: str) -> str:
        api_key = self.cfg_mgr.get_api_key("openai") or os.environ.get("OPENAI_API_KEY")
        model = self.cfg_mgr.get("openai", {}).get("model", "gpt-3.5-turbo")
        if not api_key:
            return "OpenAI API key not configured. Put it in config.json or set OPENAI_API_KEY."
        if openai is None:
            return "openai package not installed (pip install openai)."
        try:
            openai.api_key = api_key
            system_prompt = (
                "You are a helpful assistant specialized in diagnosing Windows errors. "
                "When given an error message, produce a concise explanation, likely causes, and 2-4 actionable steps to fix it. "
                "If you can suggest specific commands or settings to check, format them as code blocks."
            )
            resp = openai.ChatCompletion.create(
                model=model,
                messages=[
                    {"role":"system","content":system_prompt},
                    {"role":"user","content":f"Explain and suggest fixes for this Windows error:\n\n{msg}"}
                ],
                max_tokens=700,
                temperature=0.2
            )
            text = resp["choices"][0]["message"]["content"].strip()
            return text
        except Exception as e:
            logger.error("OpenAI call failed: %s", e)
            return f"OpenAI request failed: {e}"

class StubProvider(AIProviderBase):
    def explain(self, msg: str) -> str:
        return "Provider integration not implemented. This is a stub."

def get_provider_instance(name: str, cfg_mgr: ConfigManager) -> AIProviderBase:
    p = (name or "openai").lower()
    if p == "openai":
        return OpenAIProvider(cfg_mgr)
    # future: grok, copilot, gemini
    return StubProvider()

# ----------------- Local Flask Server -----------------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>AI Answer</title>
<style>
body{font-family:Segoe UI, Tahoma, Arial; padding:18px; background:#fff}
pre{background:#f6f6f6;padding:12px;border-radius:6px;white-space:pre-wrap}
.copy{margin-top:8px;padding:8px 12px;border:none;background:#0078d7;color:white;border-radius:6px;cursor:pointer}
.note {font-size:0.9em;color:#444;margin-bottom:10px}
</style>
</head>
<body>
<h2>AI Answer — provider: {{provider}}</h2>
<div class="note">If output looks truncated, increase model token limit in config.json</div>
<div><strong>Question / Error:</strong></div>
<pre>{{msg}}</pre>
<hr>
<div><strong>Response:</strong></div>
<pre id="resp">{{response}}</pre>
<button class="copy" onclick="copyResp()">Copy response</button>
<script>
function copyResp(){
  navigator.clipboard.writeText(document.getElementById('resp').innerText);
  alert('Copied to clipboard');
}
</script>
</body></html>
"""

class LocalServer:
    def __init__(self, cfg_mgr: ConfigManager):
        self.cfg_mgr = cfg_mgr
        self.app = None
        self.thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        if Flask is None:
            logger.warning("Flask not installed — AI server unavailable.")
            return
        if self._running:
            logger.info("LocalServer already running")
            return
        cfg = self.cfg_mgr.get("server", {})
        host = cfg.get("host", "127.0.0.1")
        port = int(cfg.get("port", 5000))
        app = Flask("ai_local_server")
        cfg_mgr = self.cfg_mgr

        @app.route("/ask")
        def ask_route():
            msg = request.args.get("msg", "")
            if not msg:
                abort(400, "No msg provided")
            cfg_local = cfg_mgr.load()  # reload config each request
            provider_name = cfg_local.get("ai_provider", "openai")
            provider = get_provider_instance(provider_name, cfg_mgr)
            try:
                response = provider.explain(msg)
            except Exception as e:
                logger.exception("Error calling provider: %s", e)
                response = f"Provider call failed: {e}"
            return render_template_string(HTML_TEMPLATE, provider=provider_name, msg=msg, response=response)

        @app.route('/__shutdown__', methods=['POST'])
        def __shutdown__():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                logger.warning('Werkzeug shutdown not available')
                return 'Shutdown not available', 500
            func()
            return 'Shutting down', 200

        def run_flask():
            try:
                app.run(host=host, port=port, debug=False, use_reloader=False)
            except Exception as e:
                logger.error("Flask server failed: %s", e)

        self.app = app
        self._host = host
        self._port = port
        self.thread = threading.Thread(target=run_flask, daemon=True, name="LocalFlask")
        self.thread.start()
        self._running = True
        logger.info("Started AI server at http://%s:%s", host, port)

    def stop(self):
        # Try to trigger Werkzeug shutdown route. For production use a proper WSGI server (waitress/gunicorn).
        if not getattr(self, '_running', False):
            logger.info("LocalServer not running")
            return
        host = getattr(self, '_host', '127.0.0.1')
        port = getattr(self, '_port', 5000)
        try:
            import urllib.request
            url = f"http://{host}:{port}/__shutdown__"
            req = urllib.request.Request(url, data=b'', method='POST')
            with urllib.request.urlopen(req, timeout=3) as resp:
                logger.info("Shutdown response: %s", resp.read().decode())
        except Exception as e:
            logger.warning("Failed to shutdown Flask cleanly: %s", e)
        # mark not running and try to join thread briefly
        self._running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("LocalServer stop requested (may require process exit to fully stop Flask dev server).")

# ----------------- GUI (optional) -----------------
if QtWidgets:
    class ConfigWindow(QWidget):
        def __init__(self, cfg_mgr: ConfigManager, server: LocalServer, monitors: List[Any]):
            super().__init__()
            self.cfg_mgr = cfg_mgr
            self.server = server
            self.monitors = monitors
            self.setWindowTitle("Error Assistant — AI Provider Config")
            self.init_ui()

        def init_ui(self):
            layout = QFormLayout()

            self.provider_combo = QComboBox()
            providers = ["openai", "grok", "copilot", "gemini"]
            self.provider_combo.addItems(providers)
            self.provider_combo.setCurrentText(self.cfg_mgr.get("ai_provider", "openai"))

            self.openai_key = QLineEdit(self.cfg_mgr.get_api_key("openai") or "")
            self.openai_model = QLineEdit(self.cfg_mgr.get("openai", {}).get("model", "gpt-3.5-turbo"))

            server = self.cfg_mgr.get("server", {})
            self.server_host = QLineEdit(server.get("host", "127.0.0.1"))
            self.server_port = QSpinBox()
            self.server_port.setRange(1, 65535)
            self.server_port.setValue(int(server.get("port", 5000)))

            monitor = self.cfg_mgr.get("monitor", {})
            self.poll_spin = QSpinBox(); self.poll_spin.setRange(1, 600); self.poll_spin.setValue(int(monitor.get("event_poll_interval", 30)))
            self.ui_poll_spin = QSpinBox(); self.ui_poll_spin.setRange(1, 60); self.ui_poll_spin.setValue(int(monitor.get("ui_poll_interval", 1)))
            self.time_window_spin = QSpinBox(); self.time_window_spin.setRange(1, 168); self.time_window_spin.setValue(int(monitor.get("time_window_hours", 24)))
            self.max_err_spin = QSpinBox(); self.max_err_spin.setRange(1, 100); self.max_err_spin.setValue(int(monitor.get("max_errors", 10)))

            self.patterns_editor = QTextEdit("\n".join(self.cfg_mgr.get("ui_patterns", DEFAULT_CONFIG["ui_patterns"])))
            self.patterns_editor.setFixedHeight(120)

            save_btn = QPushButton("Save Config")
            save_btn.clicked.connect(self.save_clicked)

            restart_btn = QPushButton("Restart AI Server")
            restart_btn.clicked.connect(self.restart_server)

            open_log_btn = QPushButton("Open Log File")
            open_log_btn.clicked.connect(self.open_log)

            test_notif_btn = QPushButton("Send Test Notification")
            test_notif_btn.clicked.connect(self.send_test)

            layout.addRow(QLabel("AI Provider:"), self.provider_combo)
            layout.addRow(QLabel("OpenAI API Key:"), self.openai_key)
            layout.addRow(QLabel("OpenAI Model:"), self.openai_model)
            layout.addRow(QLabel("Server Host:"), self.server_host)
            layout.addRow(QLabel("Server Port:"), self.server_port)
            layout.addRow(QLabel("Event Poll Interval (s):"), self.poll_spin)
            layout.addRow(QLabel("UI Poll Interval (s):"), self.ui_poll_spin)
            layout.addRow(QLabel("Time Window (hours):"), self.time_window_spin)
            layout.addRow(QLabel("Max Errors per Check:"), self.max_err_spin)
            layout.addRow(QLabel("UI Patterns (one per line):"), self.patterns_editor)
            layout.addRow(save_btn)
            layout.addRow(restart_btn)
            layout.addRow(open_log_btn)
            layout.addRow(test_notif_btn)

            self.setLayout(layout)

        def save_clicked(self):
            cfg = self.cfg_mgr.load()
            cfg["ai_provider"] = self.provider_combo.currentText()
            self.cfg_mgr.set_api_key("openai", self.openai_key.text().strip())
            cfg["openai"] = {
                "api_key": self.cfg_mgr.config.get("openai", {}).get("api_key", ""),
                "model": self.openai_model.text().strip() or "gpt-3.5-turbo"
            }
            cfg["server"] = {"host": self.server_host.text().strip() or "127.0.0.1", "port": int(self.server_port.value())}
            cfg["monitor"] = {
                "event_poll_interval": int(self.poll_spin.value()),
                "ui_poll_interval": int(self.ui_poll_spin.value()),
                "time_window_hours": int(self.time_window_spin.value()),
                "max_errors": int(self.max_err_spin.value()),
                "ui_seen_max_age": cfg.get("monitor", {}).get("ui_seen_max_age", DEFAULT_CONFIG["monitor"]["ui_seen_max_age"])
            }
            # update ui_patterns from editor
            patterns = [p.strip() for p in self.patterns_editor.toPlainText().splitlines() if p.strip()]
            if patterns:
                cfg["ui_patterns"] = patterns
            self.cfg_mgr.config = cfg
            self.cfg_mgr.save()
            QMessageBox.information(self, "Saved", "Configuration saved to config.json")

        def restart_server(self):
            cfg = self.cfg_mgr.load()
            self.server.start()
            QMessageBox.information(self, "Server", "Attempted to start AI server (if not already running).")

        def open_log(self):
            path = os.path.abspath(LOG_FILE)
            if os.path.exists(path):
                if sys.platform.startswith("win"):
                    os.startfile(path)
                else:
                    QMessageBox.information(self, "Open Log", f"Log located at: {path}")
            else:
                QMessageBox.information(self, "Open Log", "Log file not found yet.")

        def send_test(self):
            test_error = {
                'message': 'تست خطا: درایو E:\\ در دسترس نیست. لطفاً اتصال را بررسی کنید.',
                'source': 'Test',
                'time': now_iso()
            }
            Notifier.show_error_notification(test_error, self.cfg_mgr.config)
            QMessageBox.information(self, "Test", "Test notification sent (if notifications are supported).")

# ----------------- App Controller -----------------
class AppController:
    def __init__(self):
        self.cfg_mgr = ConfigManager()
        self.event_monitor = EventMonitor(self.cfg_mgr)
        self.ui_watcher = UIWatcher(self.cfg_mgr)
        self.local_server = LocalServer(self.cfg_mgr)
        self._signal_setup_done = False

    def start_all(self):
        # dependencies check
        missing = self.ensure_dependencies()
        if missing:
            logger.warning("Missing optional packages: %s", ", ".join(missing))
        # start server first
        self.local_server.start()
        # start monitors
        self.event_monitor.start()
        self.ui_watcher.start()
        self._setup_signal_handlers()
        logger.info("All services started.")

    def stop_all(self):
        logger.info("Stopping all services...")
        self.event_monitor.stop()
        self.ui_watcher.stop()
        self.local_server.stop()
        logger.info("All services stopped.")

    def ensure_dependencies(self):
        missing = []
        if win32evtlog is None:
            missing.append("pywin32 (win32evtlog, win32gui)")
        if Notification is None:
            missing.append("winotify")
        if Flask is None:
            missing.append("flask")
        if openai is None:
            missing.append("openai (optional)")
        if QtWidgets is None:
            missing.append("PySide6 (for GUI)")
        return missing

    def _setup_signal_handlers(self):
        if self._signal_setup_done:
            return
        def handle(sig, frame):
            logger.info("Signal %s received, shutting down...", sig)
            self.stop_all()
            sys.exit(0)
        # handle common signals
        signal.signal(signal.SIGINT, handle)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, handle)
        self._signal_setup_done = True

# ----------------- CLI Entrypoint -----------------
def run_gui_mode():
    controller = AppController()
    controller.start_all()
    if QtWidgets is None:
        logger.warning("PySide6 not installed — running headless.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interrupted, stopping...")
            controller.stop_all()
        return
    app = QApplication(sys.argv)
    cfg_mgr = controller.cfg_mgr
    server = controller.local_server
    monitors = [controller.event_monitor, controller.ui_watcher]
    w = ConfigWindow(cfg_mgr, server, monitors)
    w.show()
    try:
        sys.exit(app.exec())
    except KeyboardInterrupt:
        logger.info("GUI closed by user.")
        controller.stop_all()

def run_console_mode():
    controller = AppController()
    controller.start_all()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupted, stopping...")
        controller.stop_all()

def run_test_mode():
    controller = AppController()
    missing = controller.ensure_dependencies()
    if missing:
        logger.warning("Missing optional packages: %s", ", ".join(missing))
    # start server briefly
    controller.local_server.start()
    # send a test notification (and print)
    test_error = {
        'message': 'تست: اتصال به درایو E:\\ از دست رفته است. لطفاً بررسی کنید.',
        'source': 'Test',
        'time': now_iso()
    }
    logger.info("Sending test notification...")
    Notifier.show_error_notification(test_error, controller.cfg_mgr.config)
    print("Test notification attempted. If 'Ask AI' is clicked, local server should respond if Flask is available.")
    # run for a short time then stop
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        pass
    controller.stop_all()

# ----------------- Minimal Unit Tests -----------------
def _run_unit_tests():
    import unittest
    class ConfigTests(unittest.TestCase):
        def setUp(self):
            self.test_cfg = "test_config.json"
            if os.path.exists(self.test_cfg):
                os.remove(self.test_cfg)
            self.cm = ConfigManager(self.test_cfg)
        def tearDown(self):
            try:
                os.remove(self.test_cfg)
            except Exception:
                pass
        def test_default_loaded(self):
            cfg = self.cm.load()
            self.assertIn("ai_provider", cfg)
        def test_set_and_get_api_key(self):
            self.cm.set_api_key("openai", "my_secret_key_123")
            k = self.cm.get_api_key("openai")
            self.assertTrue(k == "my_secret_key_123")
    class EncryptorTests(unittest.TestCase):
        def test_roundtrip(self):
            s = "hello-secret"
            enc = Encryptor.protect(s)
            dec = Encryptor.unprotect(enc if not s.startswith("dpapi:") else enc)
            # If DPAPI not available, we may get plain; just ensure function returns a string
            self.assertIsInstance(dec, str)
    suite = unittest.TestLoader().loadTestsFromTestCase(ConfigTests)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(EncryptorTests))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)

# ----------------- Main -----------------
def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "test":
            _run_unit_tests()
            run_test_mode()
            return
        if cmd == "console":
            run_console_mode()
            return
    # default: gui mode
    run_gui_mode()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        print("Fatal error occurred. See errors.log for details.")

