import sqlite3
from contextlib import closing

DB_PATH = "database/incidents.db"

# =========================
# INCIDENTS TABLE
# =========================

def init_db():
    """Initialize DB and schema (adds lat/lon)."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()

        # Incidents table
        c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            rule_name TEXT,
            severity TEXT,
            message TEXT,
            country TEXT,
            score INTEGER,
            lat REAL,
            lon REAL
        )
        """)

        # Blocked IPs table
        c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            reason TEXT,
            blocked_at TEXT
        )
        """)

        conn.commit()


def insert_incident(ip, timestamp, rule_name, severity, message,
                    country="Unknown", score=0, lat=None, lon=None):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO incidents (ip, timestamp, rule_name, severity, message,
                               country, score, lat, lon)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, timestamp, rule_name, severity, message,
              country, score, lat, lon))
        conn.commit()


# =========================
# INCIDENT QUERIES
# =========================

def get_all_incidents(limit=0, offset=0):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        q = """
        SELECT id, ip, timestamp, rule_name, severity,
               message, country, score, lat, lon
        FROM incidents
        ORDER BY id DESC
        """
        if limit:
            q += f" LIMIT {limit} OFFSET {offset}"
        c.execute(q)
        return c.fetchall()


def get_incident_by_id(incident_id):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT id, ip, timestamp, rule_name, severity,
               message, country, score, lat, lon
        FROM incidents
        WHERE id = ?
        """, (incident_id,))
        return c.fetchone()


def get_incidents_geo(limit=500):
    """Return incidents with lat/lon for mapping."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT id, ip, timestamp, rule_name, severity,
               message, country, score, lat, lon
        FROM incidents
        WHERE lat IS NOT NULL AND lon IS NOT NULL
        ORDER BY id DESC
        LIMIT ?
        """, (limit,))
        rows = c.fetchall()

        return [
            {
                "id": r[0],
                "ip": r[1],
                "timestamp": r[2],
                "rule": r[3],
                "severity": r[4],
                "message": r[5],
                "country": r[6],
                "score": r[7],
                "lat": r[8],
                "lon": r[9],
            }
            for r in rows
        ]


# =========================
# STATISTICS
# =========================

def get_stats_by_ip():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT ip, COUNT(*) as cnt
        FROM incidents
        GROUP BY ip
        ORDER BY cnt DESC
        """)
        return c.fetchall()


def get_severity_stats():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM incidents
        GROUP BY severity
        """)
        rows = c.fetchall()
        return {row[0]: row[1] for row in rows}


def get_rule_stats():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT rule_name, COUNT(*) as cnt
        FROM incidents
        GROUP BY rule_name
        """)
        rows = c.fetchall()
        return {row[0]: row[1] for row in rows}


# =========================
# BLOCKED IPs
# =========================

def add_blocked_ip(ip, reason):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO blocked_ips (ip, reason, blocked_at)
        VALUES (?, ?, datetime('now','localtime'))
        """, (ip, reason))
        conn.commit()


def get_blocked_ips():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("""
        SELECT ip, reason, blocked_at
        FROM blocked_ips
        ORDER BY blocked_at DESC
        """)
        return c.fetchall()


# =========================
# MAINTENANCE
# =========================

def clear_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM incidents")
        c.execute("DELETE FROM blocked_ips")
        conn.commit()
