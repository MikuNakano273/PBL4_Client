import datetime
import logging
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pbl4.HistoryModel")


class HistoryModel:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        if not self.db_path or not self.db_path.exists():
            raise FileNotFoundError(f"Database not found at {self.db_path}")

        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            # Bật chế độ WAL
            conn.execute("PRAGMA journal_mode=WAL;")
            # Tăng thời gian chờ đợi lock
            conn.execute("PRAGMA busy_timeout = 30000;")
            # Đồng bộ hóa ghi dữ liệu (giảm rủi ro lỗi DB nhưng tăng hiệu năng)
            conn.execute("PRAGMA synchronous = NORMAL;")
        except Exception as e:
            logger.error(f"Failed to set PRAGMAs: {e}")
        return conn

    def get_all_quarantine(self, include_deleted: bool) -> List[Dict[str, Any]]:
        query = "SELECT * FROM quarantine_files"
        if not include_deleted:
            query += " WHERE deleted = 0"
        query += " ORDER BY quarantined_at DESC;"

        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
            return [dict(r) for r in rows]

    def get_record_by_id(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM quarantine_files WHERE id = ? LIMIT 1;", (record_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_restored_status(self, record_id: int, restored_path: str):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            conn.execute(
                "UPDATE quarantine_files SET restored = 1, restored_at = ?, restored_path = ? WHERE id = ?;",
                (now, restored_path, record_id),
            )
            conn.commit()

    def delete_record(self, record_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM quarantine_files WHERE id = ?;", (record_id,))
            conn.commit()

    def add_to_whitelist(self, file_hash: str, hash_type: str, note: str):
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO whitelist (hash, hash_type, note) VALUES (?, ?, ?);",
                (file_hash, hash_type.lower(), note),
            )
            conn.commit()

    def move_file(self, src: str, dst: str):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)

    def remove_physical_file(self, path: str):
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
