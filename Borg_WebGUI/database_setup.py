import sqlite3
import hashlib

DB_PATH = "/opt/borgweb/presets.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Benutzer-Tabelle erstellen
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
        )
    ''')

    # Standard Admin-Benutzer einfügen, falls nicht vorhanden
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_password = hashlib.sha256("admin".encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", admin_password, "admin"))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("📌 Datenbank initialisiert! Admin: admin / admin")
