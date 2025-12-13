
import sqlite3
import uuid
import datetime
import json
from src.core.config import MEMORY_DB_PATH
from src.core.logger import get_logger

logger = get_logger(__name__)

class MemoryLog:
    def __init__(self):
        self.conn = sqlite3.connect(MEMORY_DB_PATH, check_same_thread=False)
        self.init_db()

    def init_db(self):
        cur = self.conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            timestamp DATETIME,
            target_ip TEXT,
            target_port INTEGER,
            product TEXT,
            target_cve TEXT,
            status TEXT,
            notes TEXT
        )
        """)
        self.conn.commit()

    def start_run(self, ip: str, port: int, product: str, cve: str) -> int:
        # Uses legacy schema: id INTEGER PRIMARY KEY
        try:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO runs (target_ip, port, product, cve, started_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip, port, product, cve, datetime.datetime.now().timestamp(), "started"))
            self.conn.commit()
            return cur.lastrowid
        except Exception as e:
            logger.error(f"DB Error start_run: {e}")
            return 0

    def finish_run(self, run_id: int, status: str, notes: str = ""):
        try:
            cur = self.conn.cursor()
            # Legacy schema uses 'id' not 'run_id'
            cur.execute("UPDATE runs SET status = ?, notes = ?, finished_at = ? WHERE id = ?", 
                        (status, notes, datetime.datetime.now().timestamp(), run_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"DB Error finish_run: {e}")
