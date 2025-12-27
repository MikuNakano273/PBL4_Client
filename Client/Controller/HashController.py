from __future__ import annotations

import base64
import json
import threading
import time
from typing import Any, Optional

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# import HashModel
try:
    from Client.Model.HashModel import HashModel
except Exception:
    try:
        from ..Model.HashModel import HashModel
    except Exception:
        HashModel = None

# --------------- Configuration ---------------
BACKGROUND_SENDER_ENABLED = True  # Enable/Disable background sender
DEFAULT_POLL_INTERVAL_SECONDS = 30  # Server check/send interval
NETWORK_TIMEOUT_SECONDS = 15

SERVER_ADDRESS_SOURCE_URL = "https://raw.githubusercontent.com/ProgDavid7709/PBL4_Data/refs/heads/main/server_address.txt"
SERVER_ADDRESS = "0.0.0.0"
CHECK_URL = SERVER_ADDRESS + "/API/check_connection.php"
REPORT_URL = SERVER_ADDRESS + "/API/report.php"

SERVER_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCunhYywQXAbKa81dSXb
c6ehLHSwhQWm69cXwVJ90p9Orbg7raHQSwbn2VjU1jszc2JVQIvhRevPntOGcV+9
pZxEzAurxiS/QFWSgKHvf8dzRuej8qOvaNTw5qgQKqkxlQ0DCCM0uSlOvpvOiezC
Rp+bSoXn86/PDdEAiSV8YBdgqyODlOMudvv1pV7Zb2a1Elh557iL7BCHHfzsLqtf
OLPk4Suguny+EZ/o4z7ReagiPJZt59QY427yxeOrKekJt4xYnNsPuwJw+EmIVYH0
M1HTCa3GRw9mxvu84rTYK31NnUlH5vsvyhnIMRYKtInJgQ4x95whFmjaSmfN9qJY
qQIDAQAB
-----END PUBLIC KEY-----"""


# --------------- Logging ---------------
class _PrinterLogger:
    def info(self, *args, **kwargs):
        print("[INFO]", *args, flush=True)

    def debug(self, *args, **kwargs):
        print("[DEBUG]", *args, flush=True)

    def warning(self, *args, **kwargs):
        print("[WARNING]", *args, flush=True)

    def exception(self, *args, **kwargs):
        print("[EXCEPTION]", *args, flush=True)


logger = _PrinterLogger()


# --------------- Utility functions ---------------
def _pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _encrypt_payload_json(plain_json_str: str) -> dict:
    """
    Encrypt JSON using:
    - AES-256-CBC for data
    - RSA for AES key
    """

    # 1. AES key + IV
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)

    # 2. PKCS7 padding
    padded = _pad_pkcs7(plain_json_str.encode("utf-8"), AES.block_size)

    # 3. AES encrypt
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher_aes.encrypt(padded)

    # 4. Load RSA public key (embedded)
    server_pubkey = RSA.import_key(SERVER_PUBLIC_KEY_PEM)
    cipher_rsa = PKCS1_v1_5.new(server_pubkey)

    encrypted_key = cipher_rsa.encrypt(aes_key)

    # 5. Base64 encode
    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
    }


def update_server_address() -> bool:
    """Fetch SERVER_ADDRESS from github source URL."""
    global SERVER_ADDRESS, CHECK_URL, REPORT_URL

    try:
        r = requests.get(
            SERVER_ADDRESS_SOURCE_URL,
            timeout=NETWORK_TIMEOUT_SECONDS,
        )
        r.raise_for_status()

        addr = r.text.splitlines()[0].strip()
        if not addr.startswith("http"):
            return False

        addr = addr.rstrip("/")

        SERVER_ADDRESS = addr
        CHECK_URL = SERVER_ADDRESS + "/API/check_connection.php"
        REPORT_URL = SERVER_ADDRESS + "/API/report.php"

        logger.info("Updated SERVER_ADDRESS -> %s", SERVER_ADDRESS)
        return True

    except Exception as e:
        logger.info("update_server_address: no internet (%s)", e)
        return False


# --------------- Controller ---------------
class HashController:
    def __init__(
        self,
        model: Optional[Any] = None,
        poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
        enabled: Optional[bool] = None,
    ):
        if HashModel is None and model is None:
            raise ImportError(
                "HashModel could not be imported. Ensure Client.Model.HashModel exists and is importable."
            )

        if model is not None:
            self.model = model
        else:
            if HashModel is None:
                raise ImportError(
                    "HashModel is not available to construct a default model instance."
                )
            self.model = HashModel()

        self.poll_interval = poll_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._enabled = BACKGROUND_SENDER_ENABLED if enabled is None else bool(enabled)
        self._lock = threading.Lock()

        self.status: Optional[str] = None
        self.current_attempt: int = 0
        self.next_retry_time: Optional[float] = None
        self.last_response: Optional[Any] = None
        self._status_lock = threading.Lock()

        logger.info(
            "HashController initialized (enabled=%s, poll_interval=%s)",
            self._enabled,
            self.poll_interval,
        )

    # --- Background control API ---

    def set_enabled(self, enabled: bool) -> None:
        """Enable/disable the background sender at runtime."""
        with self._lock:
            self._enabled = bool(enabled)
        logger.info("HashController background enabled set to: %s", self._enabled)

    def is_enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def start(self) -> None:
        """Start the background thread if not already running and if enabled."""
        if not self.is_enabled():
            logger.info("Background sender is disabled; not starting thread.")
            return

        if self._thread and self._thread.is_alive():
            logger.info("Background thread already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker, name="HashControllerWorker", daemon=True
        )
        self._thread.start()
        logger.info("Background sender thread started.")

    def stop(self, join_timeout: float = 5.0) -> None:
        """Stop the background thread and optionally join it."""
        logger.info("Stopping background sender thread...")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=join_timeout)
            if self._thread.is_alive():
                logger.warning("Background thread did not stop within timeout.")
            else:
                logger.info("Background thread stopped.")
        self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # --- Convenience: external persistence API ---
    def add_hash_record(
        self, hash_value, type="sha256", malware_name="", rule_match=""
    ):
        try:
            try:
                res = self.model.add_hash(
                    hash_value,
                    type=type,
                    malware_name=malware_name,
                    rule_match=rule_match,
                )
            except TypeError:
                res = self.model.add_hash(hash_value, type, malware_name, rule_match)

            if res:
                logger.debug("Added hash record via HashController: %s", hash_value)
            else:
                logger.debug(
                    "Model reported failure when adding hash record: %s", hash_value
                )
            return bool(res)
        except Exception as e:
            logger.exception("Exception while adding hash record: %s", e)
            return False

    # --- Sending API ---

    def send_now(self) -> bool:
        with getattr(self, "_status_lock", threading.Lock()):
            self.status = None
            self.current_attempt = 0
            self.next_retry_time = None
            self.last_response = None

        try:
            entries = self.model.get_all()
        except Exception as e:
            logger.exception("send_now: Failed reading entries from HashModel: %s", e)
            with getattr(self, "_status_lock", threading.Lock()):
                self.status = "failure"
                self.last_response = str(e)
            return False

        if not entries:
            logger.info("send_now: no entries to send (JSON empty).")
            with getattr(self, "_status_lock", threading.Lock()):
                self.status = "no_entries"
                self.last_response = None
            return True  # nothing to send; treat as success

        logger.info(
            "send_now: found %d entries; performing server availability check...",
            len(entries),
        )

        # Check network connectivity & server status (expects JSON {"status":"ok"} or {"status":"busy"})
        try:
            resp = requests.get(CHECK_URL, timeout=NETWORK_TIMEOUT_SECONDS)
            resp.raise_for_status()
            logger.info(
                "send_now: check_connection response code=%s text=%s",
                resp.status_code,
                repr(resp.text),
            )
            try:
                j = resp.json()
                logger.info("send_now: check_connection returned JSON: %s", j)
                with getattr(self, "_status_lock", threading.Lock()):
                    self.last_response = j
                status = j.get("status", "").lower()
            except Exception:
                logger.warning(
                    "send_now: check_connection returned non-JSON response; aborting send. Raw: %s",
                    repr(resp.text),
                )
                with getattr(self, "_status_lock", threading.Lock()):
                    self.status = "no_connection"
                    self.last_response = f"Invalid JSON: {repr(resp.text)}"
                return False

            if status == "busy":
                logger.info("send_now: server returned 'busy'. Will retry later.")
                with getattr(self, "_status_lock", threading.Lock()):
                    self.status = "failure"
                    self.next_retry_time = time.time() + self.poll_interval
                return False
            elif status != "ok":
                logger.warning(
                    "send_now: server check_connection returned unexpected status: %s",
                    status,
                )
                with getattr(self, "_status_lock", threading.Lock()):
                    self.status = "no_connection"
                    self.last_response = {"status": status}
                return False
            else:
                logger.info(
                    "send_now: server returned 'ok'; will attempt to send (up to 3 tries)."
                )
        except requests.RequestException as e:
            logger.info("send_now: Network/server check failed or no network: %s", e)
            with getattr(self, "_status_lock", threading.Lock()):
                self.status = "no_connection"
                self.last_response = str(e)
            return False
        except Exception as e:
            logger.exception("send_now: Unexpected error during server check: %s", e)
            with getattr(self, "_status_lock", threading.Lock()):
                self.status = "failure"
                self.last_response = str(e)
            return False

        try:
            plain_json_str = json.dumps(entries, ensure_ascii=False)
            payload = _encrypt_payload_json(plain_json_str)
        except Exception as e:
            logger.exception("send_now: Failed to prepare encrypted payload: %s", e)
            with getattr(self, "_status_lock", threading.Lock()):
                self.status = "failure"
                self.last_response = str(e)
            return False

        headers = {"Content-Type": "application/json"}

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            with getattr(self, "_status_lock", threading.Lock()):
                self.current_attempt = attempt
                self.status = "sending"
                self.next_retry_time = None

            logger.info(
                "send_now: Attempt %d/%d to POST report...", attempt, max_attempts
            )
            try:
                resp = requests.post(
                    REPORT_URL,
                    json=payload,
                    headers=headers,
                    timeout=NETWORK_TIMEOUT_SECONDS,
                )
                logger.info("send_now: Report POST status: %s", resp.status_code)
                logger.info("send_now: Report POST response text: %s", resp.text)

                try:
                    server_json = resp.json() if resp.text else {}
                    logger.info("send_now: Report POST returned JSON: %s", server_json)
                    with getattr(self, "_status_lock", threading.Lock()):
                        self.last_response = server_json
                except Exception:
                    server_json = None
                    logger.debug("send_now: Report POST returned non-JSON response.")
                    with getattr(self, "_status_lock", threading.Lock()):
                        self.last_response = resp.text

                if resp.status_code == 200:
                    try:
                        server_status = ""
                        if isinstance(server_json, dict):
                            server_status = server_json.get("status", "").lower()
                        if server_status and server_status not in ("ok", "success"):
                            logger.warning(
                                "send_now: Server returned status '%s' after report; not clearing local file.",
                                server_status,
                            )
                        else:
                            try:
                                self.model.clear()
                                logger.info(
                                    "send_now: Uploaded hash JSON and cleared local file."
                                )
                                with getattr(self, "_status_lock", threading.Lock()):
                                    self.status = "success"
                                    self.current_attempt = 0
                                    self.next_retry_time = None
                                return True
                            except Exception as e:
                                logger.exception(
                                    "send_now: Uploaded but failed to clear local file: %s",
                                    e,
                                )
                                with getattr(self, "_status_lock", threading.Lock()):
                                    self.status = "failure"
                                    self.last_response = str(e)
                                return False
                    except Exception:
                        try:
                            self.model.clear()
                            logger.info(
                                "send_now: Uploaded hash JSON (non-JSON server response) and cleared local file."
                            )
                            with getattr(self, "_status_lock", threading.Lock()):
                                self.status = "success"
                                self.current_attempt = 0
                                self.next_retry_time = None
                            return True
                        except Exception as e:
                            logger.exception(
                                "send_now: Uploaded but failed to clear local file: %s",
                                e,
                            )
                            with getattr(self, "_status_lock", threading.Lock()):
                                self.status = "failure"
                                self.last_response = str(e)
                            return False
                else:
                    logger.warning(
                        "send_now: Report POST failed (status %s): %s",
                        resp.status_code,
                        resp.text,
                    )

            except requests.RequestException as e:
                logger.info(
                    "send_now: Failed to POST report (network error) on attempt %d: %s",
                    attempt,
                    e,
                )
                with getattr(self, "_status_lock", threading.Lock()):
                    self.last_response = str(e)
            except Exception as e:
                logger.exception(
                    "send_now: Unexpected error while posting report on attempt %d: %s",
                    attempt,
                    e,
                )
                with getattr(self, "_status_lock", threading.Lock()):
                    self.last_response = str(e)

            if attempt < max_attempts:
                backoff = 1  # seconds between attempts in this sender implementation
                with getattr(self, "_status_lock", threading.Lock()):
                    self.status = "sending"
                    self.next_retry_time = time.time() + backoff
                logger.info(
                    "send_now: Attempt %d failed; will retry (next attempt soon).",
                    attempt,
                )
                time.sleep(backoff)
            else:
                with getattr(self, "_status_lock", threading.Lock()):
                    self.status = "failure"
                    self.current_attempt = 0
                    self.next_retry_time = time.time() + self.poll_interval
                logger.warning(
                    "send_now: All %d attempts to send report failed; will wait and retry later.",
                    max_attempts,
                )
                return False

        # we should not reach here, but just in case
        with getattr(self, "_status_lock", threading.Lock()):
            self.status = "failure"
        return False

    # --- Worker thread ---

    def _worker(self) -> None:
        """
        Vòng lặp chính:
        1. Check model -> Lỗi? Đợi 30s rồi continue (quay lại B1).
        2. Check net cơ bản -> Lỗi? Đợi 30s rồi continue.
        3. Send -> Ok? Đợi 30s quay lại B1.
        """
        logger.info(f"Worker running. Interval: {self.poll_interval}s")

        while not self._stop_event.is_set():
            if not self.is_enabled():
                self._stop_event.wait(self.poll_interval)
                continue

            # --- BƯỚC 1: Check Json---
            try:
                entries = self.model.get_all()
                if not entries:
                    logger.info("Worker: no entries (empty).")
                else:
                    logger.info(f"Worker: found {len(entries)} entries.")
            except Exception as e:
                logger.exception(f"Worker: error reading entries: {e}")

                with self._status_lock:
                    self.status = "failure"
                    self.last_response = f"Read error: {e}"

                self._stop_event.wait(self.poll_interval)
                continue

            if not entries:
                self._stop_event.wait(self.poll_interval)
                continue

            # --- BƯỚC 2: Check mạng (qua update_server_address) ---
            logger.info("Worker: checking internet (update server address)...")

            if not update_server_address():
                with self._status_lock:
                    self.status = "no_connection"
                    self.last_response = "No internet / cannot fetch server address"

                self._stop_event.wait(self.poll_interval)
                continue

            # --- BƯỚC 3: Gửi ---
            logger.info("Worker: invoking send_now()...")
            try:
                # send_now tự lo logic retry 3 lần bên trong
                self.send_now()
            except Exception as e:
                logger.exception(f"Worker: crash in send_now: {e}")

            self._stop_event.wait(self.poll_interval)

        logger.info("Worker exiting.")


# --------------- Convenience module-level controller ---------------

_default_controller: Optional[HashController] = None


def get_hash_controller() -> HashController:
    global _default_controller
    if _default_controller is None:
        _default_controller = HashController()
    return _default_controller


def get_default_controller() -> HashController:
    """Backward-compatible alias for get_hash_controller()."""
    return get_hash_controller()


if BACKGROUND_SENDER_ENABLED:
    try:
        pass
    except Exception:
        pass
