import sqlite3

def init_db():
    conn = sqlite3.connect("netpulse.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        bytes_captured INTEGER,
        packet_count INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        threat_level TEXT,
        summary TEXT
    )
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")

if __name__ == "__main__":
    init_db()
