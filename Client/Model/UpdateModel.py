from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("pbl4.UpdateModel")
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)
    logger.setLevel(logging.INFO)


PROGRAMDATA_DIR = Path.cwd()
DEFAULT_DB_PATH = PROGRAMDATA_DIR / "full_hash.db"
GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/ProgDavid7709/PBL4_Data/main/database"
)
DATABASE_VERSION_TXT = GITHUB_RAW_BASE + "/database_version.txt"


class UpdateResult:
    def __init__(
        self,
        success: bool,
        applied: List[int],
        message: str = "",
        error: Optional[str] = None,
    ):
        self.success = success
        self.applied = applied
        self.message = message
        self.error = error

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "applied": self.applied,
            "message": self.message,
            "error": self.error,
        }


class UpdateModel:
    def __init__(
        self, db_path: Optional[str] = None, github_raw_base: Optional[str] = None
    ) -> None:
        self.db_path = Path(db_path) if db_path else Path(DEFAULT_DB_PATH)
        self.github_raw_base = github_raw_base or GITHUB_RAW_BASE
        self._lock = threading.RLock()

    # -------------------------
    # Helper I/O and DB methods
    # -------------------------
    def _open_db(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=30)
            return conn
        except Exception as exc:
            logger.exception("Failed to open DB %s: %s", self.db_path, exc)
            raise

    def get_local_db_version(self) -> int:
        try:
            # If the DB file doesn't exist, treat as version 0 and do NOT create it.
            if not self.db_path.exists():
                logger.debug(
                    "DB path %s does not exist; treating local version as 0",
                    self.db_path,
                )
                return 0

            conn = self._open_db()
        except Exception:
            logger.debug("DB not accessible; treating local version as 0")
            return 0

        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT value FROM db_info WHERE key = ? LIMIT 1;", ("db_version",)
            )
            row = cur.fetchone()
            if row and row[0] is not None:
                try:
                    return int(row[0])
                except Exception:
                    logger.warning(
                        "Non-integer db_version stored in db_info: %r", row[0]
                    )
                    return 0
            return 0
        except sqlite3.Error as exc:
            logger.warning("Error reading db_info.db_version: %s", exc)
            return 0
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _set_local_db_version(self, conn: sqlite3.Connection, version: int) -> None:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO db_info(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            ("db_version", str(version)),
        )

    # -------------------------
    # Remote fetch utilities
    # -------------------------
    def _fetch_url_text(self, url: str, timeout: int = 20) -> str:
        headers = {"User-Agent": "PBL4-Client-UpdateModel/1.0"}
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return raw.decode("utf-8", errors="replace")
        except HTTPError as he:
            logger.debug("HTTP error fetching %s: %s", url, he)
            raise
        except URLError as ue:
            logger.debug("URL error fetching %s: %s", url, ue)
            raise

    def fetch_remote_latest_version(self) -> int:
        txt_url = f"{self.github_raw_base}/database_version.txt"
        logger.debug("Fetching remote database version from %s", txt_url)
        content = self._fetch_url_text(txt_url)
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                v = int(line.split()[0])
                logger.debug("Remote highest database version: %d", v)
                return v
            except Exception:
                raise ValueError(
                    f"database_version.txt does not start with an integer: {line!r}"
                )
        raise ValueError("database_version.txt is empty or invalid")

    def _download_sql_for_version(self, v: int) -> str:
        url = f"{self.github_raw_base}/v{v}/v{v}.sql"
        logger.info("Downloading SQL for version %d from %s", v, url)
        return self._fetch_url_text(url)

    # -------------------------
    # Update application logic
    # -------------------------
    def _apply_sql_script(
        self, conn: sqlite3.Connection, sql_text: str
    ) -> Tuple[bool, Optional[str]]:
        try:
            conn.executescript(sql_text)
            return True, None
        except sqlite3.Error as exc:
            logger.exception("Failed to execute SQL script: %s", exc)
            return False, str(exc)

    def check_and_update(self, dry_run: bool = False) -> UpdateResult:
        with self._lock:
            logger.info("Checking for hash DB updates (db_path=%s) ...", self.db_path)
            # 1) Get local version
            local_v = self.get_local_db_version()
            logger.info("Local DB version: %d", local_v)

            # 2) Fetch remote highest version
            try:
                remote_v = self.fetch_remote_latest_version()
            except Exception as exc:
                msg = f"Failed to fetch remote version: {exc}"
                logger.warning(msg)
                return UpdateResult(False, [], message=msg, error=str(exc))

            if remote_v <= local_v:
                msg = f"No update necessary (local={local_v}, remote={remote_v})"
                logger.info(msg)
                return UpdateResult(True, [], message=msg)

            # 3) Apply each missing version in ascending order
            applied_versions: List[int] = []
            for target_v in range(local_v + 1, remote_v + 1):
                logger.info("Preparing to apply update v%d", target_v)
                try:
                    sql_text = self._download_sql_for_version(target_v)
                except Exception as exc:
                    msg = f"Failed to download SQL for v{target_v}: {exc}"
                    logger.error(msg)
                    return UpdateResult(
                        False, applied_versions, message=msg, error=str(exc)
                    )

                # If dry_run, don't touch DB, just report
                if dry_run:
                    logger.info(
                        "Dry run enabled - would apply v%d (skipping actual execute)",
                        target_v,
                    )
                    applied_versions.append(target_v)
                    continue

                # Execute script within a transaction
                try:
                    conn = self._open_db()
                except Exception as exc:
                    msg = f"Failed to open DB for applying v{target_v}: {exc}"
                    logger.error(msg)
                    return UpdateResult(
                        False, applied_versions, message=msg, error=str(exc)
                    )

                try:
                    conn = self._open_db()
                    try:
                        # executescript() tự BEGIN/COMMIT
                        ok, err = self._apply_sql_script(conn, sql_text)
                        if not ok:
                            conn.close()
                            msg = f"Applying v{target_v} failed: {err}"
                            return UpdateResult(
                                False, applied_versions, message=msg, error=err
                            )

                        # Update version (cũng nằm trong transaction của executescript)
                        self._set_local_db_version(conn, target_v)

                        # Commit thủ công bằng connection (KHÔNG dùng SQL COMMIT)
                        conn.commit()

                        applied_versions.append(target_v)
                        logger.info("Successfully applied v%d", target_v)

                    except Exception as exc:
                        conn.rollback()
                        msg = f"Unexpected error while applying v{target_v}: {exc}"
                        logger.exception(msg)
                        return UpdateResult(
                            False, applied_versions, message=msg, error=str(exc)
                        )
                    finally:
                        conn.close()
                    applied_versions.append(target_v)
                    logger.info("Successfully applied v%d", target_v)
                except Exception as exc:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                    msg = f"Unexpected error while applying v{target_v}: {exc}"
                    logger.exception(msg)
                    return UpdateResult(
                        False, applied_versions, message=msg, error=str(exc)
                    )
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

            # Completed all versions
            msg = (
                f"Applied versions: {applied_versions}"
                if applied_versions
                else "No changes applied"
            )
            logger.info("Update complete: %s", msg)
            return UpdateResult(True, applied_versions, message=msg)

    # -------------------------
    # Optional settings helpers
    # -------------------------
    def get_programdata_settings_path(self) -> Path:
        return PROGRAMDATA_DIR / "settings.json"

    def load_program_settings(self) -> Dict:
        defaults = {
            "start_with_windows": False,
            "autostart_all_users": False,
            "shortcut_name": "PBL4_Client",
            "auto_update_hash": True,
        }
        p = self.get_programdata_settings_path()
        try:
            if p.exists():
                with p.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        merged = {**defaults, **data}
                        return merged
        except Exception as exc:
            logger.debug("Failed to load program settings: %s", exc)
        return defaults

    def save_program_settings(self, settings: Dict) -> None:
        try:
            PROGRAMDATA_DIR.mkdir(parents=True, exist_ok=True)
            tmp = self.get_programdata_settings_path().with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
            tmp.replace(self.get_programdata_settings_path())
        except Exception as exc:
            logger.warning("Failed to save program settings: %s", exc)
            raise

    def auto_update_on_launch_if_enabled(self) -> Optional[UpdateResult]:
        try:
            s = self.load_program_settings()
            if not bool(s.get("auto_update_hash", True)):
                logger.info("Auto update on launch disabled by settings")
                return None
            # Run update (synchronous). Caller may choose to run this in a thread.
            return self.check_and_update(dry_run=False)
        except Exception as exc:
            logger.exception("auto_update_on_launch_if_enabled failed: %s", exc)
            return UpdateResult(
                False, [], message="Auto-update startup failed", error=str(exc)
            )


if __name__ == "__main__":
    um = UpdateModel()
    logger.info("Local DB path: %s", um.db_path)
    res = um.check_and_update(dry_run=True)
    print(json.dumps(res.to_dict(), indent=2))
