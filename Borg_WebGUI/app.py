import os
import sqlite3
import subprocess
import json
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, render_template

app = Flask(__name__)
app.secret_key = "qwertz"  # ⚠ Ändere das für mehr Sicherheit

#BORG_REPO = "/home/backup"  # Passe den Pfad zu deinem Borg-Repo an
def get_borg_repo():
    """Lädt den Storage Box Pfad aus den Einstellungen"""
    with open(SETTINGS_FILE, "r") as file:
        config = json.load(file)
    storage_ip = config.get("storage_ip")
    storage_user = config.get("storage_user")
    storage_port = config.get("storage_port")
    storage_path = config.get("storage_path")
    backup_folder = config.get("backup_folder")

    return f"ssh://{storage_user}@{storage_ip}:{storage_port}{storage_path}/{backup_folder}"

DB_PATH = "/opt/borgweb/presets.db"  # SQLite-Datenbank für Presets

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# 🔐 Benutzer einloggen
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = hashlib.sha256(data.get("password").encode()).hexdigest()  # Hashen des Passworts!

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        session["username"] = username
        session["role"] = user[0]
        return jsonify({"status": "success", "message": "Erfolgreich eingeloggt!"})
    else:
        return jsonify({"status": "error", "message": "Falscher Benutzername oder Passwort"}), 401


# 🔐 Benutzer abmelden
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# 🔐 Benutzerliste abrufen (nur Admin)
@app.route("/get_users", methods=["GET"])
def get_users():
    if "username" not in session or session["role"] != "admin":
        return jsonify({"status": "error", "message": "Zugriff verweigert"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()

    return jsonify({"status": "success", "users": [{"id": u[0], "username": u[1], "role": u[2]} for u in users]})

# 🔐 Neuen Benutzer anlegen (nur Admin)
@app.route("/add_user", methods=["POST"])
def add_user():
    if "username" not in session or session["role"] != "admin":
        return jsonify({"status": "error", "message": "Zugriff verweigert"}), 403

    data = request.json
    username = data.get("username")
    password = hashlib.sha256(data.get("password").encode()).hexdigest()
    role = data.get("role")

    if role not in ["admin", "user"]:
        return jsonify({"status": "error", "message": "Ungültige Rolle"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        return jsonify({"status": "success", "message": "Benutzer erfolgreich erstellt"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Benutzername existiert bereits"}), 400
    finally:
        conn.close()

@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.json
    username = data.get('username')
    new_password = data.get('new_password')

    if not username or not new_password:
        return jsonify({"status": "error", "message": "Fehlende Felder!"}), 400

    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()

    try:
        conn = sqlite3.connect('/opt/borgweb/presets.db')  # Passe den DB-Pfad an
        cursor = conn.cursor()

        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": f"Passwort für '{username}' geändert!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/delete_user", methods=["POST"])
def delete_user():
    """Löscht einen Benutzer (nur Admins erlaubt)"""
    if "username" not in session or session["role"] != "admin":
        return jsonify({"status": "error", "message": "Zugriff verweigert"}), 403

    data = request.json
    username = data.get("username")

    if not username or username == "admin":  # Admin kann nicht gelöscht werden!
        return jsonify({"status": "error", "message": "Ungültiger Benutzername oder Admin kann nicht gelöscht werden!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": f"Benutzer {username} wurde gelöscht!"})


# 📌 SQLite-Datenbankverbindung
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS autobackups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        preset_name TEXT NOT NULL,
        cron_schedule TEXT NOT NULL
    )
    ''')
    return conn

@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("index.html")

@app.route("/login_page")
def login_page():
    return render_template("login.html")


@app.route("/")
def home():
    return send_from_directory("/opt/borgweb", "index.html")

@app.route("/backups")
def backups_page():
    return send_from_directory("/opt/borgweb", "backups.html")

@app.route("/presets")
def presets_page():
    return send_from_directory("/opt/borgweb", "presets.html")

@app.route("/manage")
def manage_page():
    return send_from_directory("/opt/borgweb", "manage.html")

@app.route("/autobackups")
def autobackups_page():
    return send_from_directory("/opt/borgweb", "autobackups.html")

@app.route("/settings")
def settings_page():
    return send_from_directory("/opt/borgweb", "settings.html")


@app.route("/list_preset_names", methods=["GET"])
def list_preset_names():
    """Gibt eine Liste aller gespeicherten Presets zurück"""
    conn = get_db_connection()
    presets = conn.execute("SELECT name FROM presets").fetchall()
    conn.close()

    preset_names = [row["name"] for row in presets]
    return jsonify({"status": "success", "presets": preset_names})

@app.route("/restore_multiple_backups", methods=["POST"])
def restore_multiple_backups():
    """Stellt mehrere Backups von der Storage Box an einem Zielpfad wieder her"""
    try:
        data = request.json
        archive_names = data.get("archive_names")
        target_path = data.get("target_path")

        if not archive_names or not isinstance(archive_names, list):
            return jsonify({"status": "error", "message": "Keine gültigen Backups ausgewählt!"}), 400
        if not target_path or not isinstance(target_path, str):
            return jsonify({"status": "error", "message": "Zielpfad fehlt oder ungültig!"}), 400

        borg_repo = get_borg_repo()

        # Passphrase aus den Settings abrufen
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)
        borg_passphrase = config.get("borg_passphrase", "")

        for archive_name in archive_names:
            cmd = [
                "borg", "extract",
                f"{borg_repo}::{archive_name}",
                "--strip-components", "1",
                "--progress"
            ]

            subprocess.run(cmd, check=True, env={"BORG_PASSPHRASE": borg_passphrase}, cwd=target_path)

        return jsonify({"status": "success", "message": f"{len(archive_names)} Backups wurden erfolgreich nach {target_path} wiederhergestellt!"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Fehler bei der Wiederherstellung: {str(e)}"}), 500



@app.route("/delete_multiple_backups", methods=["POST"])
def delete_multiple_backups():
    """Löscht mehrere Backups von der Storage Box mit automatischer Passphrase"""
    try:
        data = request.json
        archive_names = data.get("archive_names")

        if not archive_names or not isinstance(archive_names, list):
            return jsonify({"status": "error", "message": "Keine gültigen Backups ausgewählt!"}), 400

        borg_repo = get_borg_repo()

        # Passphrase aus den Settings abrufen
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)
        borg_passphrase = config.get("borg_passphrase", "")

        for archive_name in archive_names:
            cmd = ["borg", "delete", f"{borg_repo}::{archive_name}"]
            subprocess.run(cmd, check=True, env={"BORG_PASSPHRASE": borg_passphrase})

        return jsonify({"status": "success", "message": f"{len(archive_names)} Backups wurden gelöscht!"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500




SETTINGS_FILE = "/opt/borgweb/storage_config.json"

@app.route("/get_storage_config", methods=["GET"])
def get_storage_config():
    """Lädt die gespeicherte Storage-Box-Konfiguration"""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)
        return jsonify({"status": "success", "config": config})
    return jsonify({"status": "error", "message": "Keine Konfiguration gefunden"}), 404

import subprocess

@app.route("/set_storage_config", methods=["POST"])
def set_storage_config():
    """Speichert die Storage-Box-Konfiguration und erstellt den Ordner auf dem Backup-Server"""
    try:
        data = request.json
        with open(SETTINGS_FILE, "w") as file:
            json.dump(data, file, indent=4)

        # Backup-Ordner auf dem Remote-Server erstellen
        storage_ip = data.get("storage_ip")
        storage_user = data.get("storage_user")
        storage_port = data.get("storage_port")
        storage_password = data.get("storage_password")
        storage_path = data.get("storage_path")  # Hauptpfad
        backup_folder = data.get("backup_folder")  # Neuer Backup-Ordner

        if storage_ip and storage_user and storage_path and backup_folder:
            remote_full_path = f"{storage_path}/{backup_folder}"

            # 🔹 Schritt 1: Ordner auf dem Backup-Server erstellen
            create_cmd = [
                "sshpass", "-p", storage_password,
                "ssh", "-p", storage_port, f"{storage_user}@{storage_ip}",
                f"mkdir -p {remote_full_path}"
            ]
            subprocess.run(create_cmd, check=True)

        return jsonify({"status": "success", "message": "Konfiguration gespeichert & Backup-Ordner erstellt!"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Fehler beim Erstellen des Backup-Ordners: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/initialize_borg", methods=["POST"])
def initialize_borg():
    """Initialisiert das Borg-Repository auf dem Backup-Server mit einer vorgegebenen Passphrase"""
    try:
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)

        storage_ip = config.get("storage_ip")
        storage_user = config.get("storage_user")
        storage_port = config.get("storage_port")
        storage_password = config.get("storage_password")
        storage_path = config.get("storage_path")
        backup_folder = config.get("backup_folder")
        borg_passphrase = config.get("borg_passphrase")  # NEU: Borg-Passphrase

        if storage_ip and storage_user and storage_path and backup_folder and borg_passphrase:
            remote_full_path = f"{storage_path}/{backup_folder}"

            # 🔹 Borg-Repository initialisieren mit vorgegebener Passphrase
            init_cmd = [
                "borg", "init",
                "--encryption=repokey",
                f"ssh://{storage_user}@{storage_ip}:{storage_port}{remote_full_path}"
            ]

            # Borg-Passphrase als Umgebungsvariable setzen
            subprocess.run(init_cmd, check=True, env={"BORG_PASSPHRASE": borg_passphrase})

        return jsonify({"status": "success", "message": "Borg-Repository wurde erfolgreich initialisiert!"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Fehler bei Borg Init: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


        # Backup-Ordner auf dem Remote-Server erstellen

        storage_ip = data.get("storage_ip")
        storage_user = data.get("storage_user")
        storage_port = data.get("storage_port")
        storage_password = data.get("storage_password")
        storage_path = data.get("storage_path")  # Hauptpfad
        backup_folder = data.get("backup_folder")  # Neuer Backup-Ordner

        if storage_ip and storage_user and storage_path and backup_folder:
            remote_full_path = f"{storage_path}/{backup_folder}"

            # Erstellen des Ordners über SSH
            cmd = [
                "sshpass", "-p", storage_password,
                "ssh", "-p", storage_port, f"{storage_user}@{storage_ip}",
                f"mkdir -p {remote_full_path}"
            ]
            subprocess.run(cmd, check=True)

        return jsonify({"status": "success", "message": "Konfiguration gespeichert & Backup-Ordner erstellt!"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Fehler beim Erstellen des Backup-Ordners: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# 🔥 Rekursive Funktion zum Abrufen der Verzeichnisstruktur
def get_directory_structure(root_dir, max_depth=3, current_depth=0):
    if current_depth > max_depth:
        return None  # Verhindert zu tiefe Rekursion

    try:
        directories = []
        for entry in os.scandir(root_dir):
            if entry.is_dir(follow_symlinks=False):  # Nur Verzeichnisse
                subdir = get_directory_structure(entry.path, max_depth, current_depth + 1)
                directories.append({
                    "name": entry.name,
                    "path": entry.path,
                    "children": subdir if subdir else []
                })
        return directories
    except PermissionError:
        return None  # Keine Berechtigung zum Lesen des Verzeichnisses

@app.route("/list_folders", methods=["GET"])
def list_folders():
    base_path = "/"  # Das Root-Verzeichnis
    structure = get_directory_structure(base_path)
    return jsonify({"status": "success", "directories": structure})


# 🔥 Auto-Backup in die Datenbank und Cron hinzufügen
@app.route("/add_autobackup", methods=["POST"])
def add_autobackup():
    try:
        data = request.json
        preset_name = data.get("preset_name")
        cron_schedule = data.get("cron_schedule")  # Beispiel: "0 2 * * *" für täglich um 2 Uhr

        if not preset_name or not cron_schedule:
            return jsonify({"status": "error", "message": "Preset-Name und Cron-Zeitplan erforderlich!"}), 400

        conn = get_db_connection()
        preset = conn.execute("SELECT * FROM presets WHERE name = ?", (preset_name,)).fetchone()
        if not preset:
            conn.close()
            return jsonify({"status": "error", "message": "Preset nicht gefunden!"}), 404
        
        # Auto-Backup in DB speichern
        conn.execute("INSERT INTO autobackups (preset_name, cron_schedule) VALUES (?, ?)", (preset_name, cron_schedule))
        conn.commit()
        conn.close()

        # Cronjob setzen
        cron_job = f"{cron_schedule} root /usr/bin/curl -X POST -H 'Content-Type: application/json' -d '{{\"preset_name\": \"{preset_name}\"}}' http://127.0.0.1:5000/backup_preset\n"
        with open("/etc/cron.d/borg_autobackups", "a") as cronfile:
            cronfile.write(cron_job)

        return jsonify({"status": "success", "message": f"Auto-Backup für {preset_name} geplant mit '{cron_schedule}'"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# 🔥 Liste aller Auto-Backups anzeigen
@app.route("/list_autobackups", methods=["GET"])
def list_autobackups():
    conn = get_db_connection()
    autobackups = conn.execute("SELECT * FROM autobackups").fetchall()
    conn.close()

    autobackups_list = [{"preset_name": row["preset_name"], "cron_schedule": row["cron_schedule"]} for row in autobackups]
    return jsonify({"status": "success", "autobackups": autobackups_list})


# 🔥 Auto-Backup löschen (aus Datenbank und Cron entfernen)
@app.route("/delete_autobackup", methods=["POST"])
def delete_autobackup():
    try:
        data = request.json
        preset_name = data.get("preset_name")

        conn = get_db_connection()
        conn.execute("DELETE FROM autobackups WHERE preset_name = ?", (preset_name,))
        conn.commit()
        conn.close()

        # Cronjob entfernen
        with open("/etc/cron.d/borg_autobackups", "r") as cronfile:
            lines = cronfile.readlines()
        with open("/etc/cron.d/borg_autobackups", "w") as cronfile:
            for line in lines:
                if preset_name not in line:
                    cronfile.write(line)

        return jsonify({"status": "success", "message": f"Auto-Backup {preset_name} entfernt!"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# 🔥 Manuelles Backup starten
@app.route("/create_backup", methods=["POST"])
def create_backup():
    """Erstellt ein manuelles Backup auf der Storage Box mit Namensvergabe und automatischem Passwort"""
    try:
        data = request.json
        backup_name = data.get("backup_name", "").strip()
        source_paths = data.get("source_paths", [])  # Liste von Pfaden

        if not backup_name:
            return jsonify({"status": "error", "message": "Kein Backup-Name angegeben!"}), 400
        if not source_paths or not isinstance(source_paths, list):
            return jsonify({"status": "error", "message": "Keine gültigen Backup-Pfade angegeben!"}), 400

        borg_repo = get_borg_repo()

        # Passphrase & SSH-Passwort aus den Settings abrufen
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)
        borg_passphrase = config.get("borg_passphrase", "")
        storage_password = config.get("storage_password", "")

        archive_name = f"{backup_name}-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        # Verwende `sshpass`, um das SSH-Passwort automatisch zu übergeben
        cmd = [
            "sshpass", "-p", storage_password,
            "borg", "create", "--lock-wait", "20", f"{borg_repo}::{archive_name}"
        ] + source_paths

        # Passphrase und SSH-Passwort übergeben
        subprocess.run(cmd, check=True, env={"BORG_PASSPHRASE": borg_passphrase})

        return jsonify({"status": "success", "message": f"Backup {archive_name} auf der Storage Box erstellt"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500






# 🔥 Liste aller Backups anzeigen
@app.route("/list_backups", methods=["GET"])
def list_backups():
    """Listet alle Backups auf der Storage Box auf, ohne nach der Passphrase zu fragen"""
    try:
        borg_repo = get_borg_repo()  # Holt den Storage Box Pfad

        # Passphrase aus den Settings abrufen
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)
        borg_passphrase = config.get("borg_passphrase", "")

        # Borg-Befehl zum Auflisten der Backups
        cmd = ["borg", "list", "--format", "{archive}{NL}", borg_repo]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, env={"BORG_PASSPHRASE": borg_passphrase})

        backups = result.stdout.strip().split("\n")

        return jsonify({"status": "success", "backups": backups})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Fehler beim Auflisten der Backups: {str(e)}"}), 500



@app.route("/delete_backup", methods=["POST"])
def delete_backup():
    try:
        data = request.json
        archive_name = data.get("archive_name")

        if not archive_name:
            return jsonify({"status": "error", "message": "Backup-Name fehlt!"}), 400

        borg_repo = get_borg_repo()  # Richtiges Borg-Repo ermitteln

        # Backup in Borg löschen
        cmd = ["borg", "delete", f"{borg_repo}::{archive_name}"]
        subprocess.run(cmd, check=True)

        return jsonify({"status": "success", "message": f"Backup {archive_name} wurde gelöscht!"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500



# 🔥 Backup wiederherstellen
@app.route("/restore", methods=["POST"])
def restore_backup():
    try:
        data = request.json
        archive_name = data.get("archive_name")
        target_path = data.get("target_path", "/home/restore")

        if not archive_name:
            return jsonify({"status": "error", "message": "Archivname fehlt!"}), 400

        os.makedirs(target_path, exist_ok=True)

        # Backup extrahieren
        cmd = ["borg", "extract", f"{BORG_REPO}::{archive_name}"]
        subprocess.run(cmd, cwd=target_path, check=True)

        return jsonify({"status": "success", "message": f"Backup {archive_name} wurde in {target_path} wiederhergestellt"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# 🔥 Backup-Preset speichern
@app.route("/add_preset", methods=["POST"])
def add_preset():
    try:
        data = request.json
        preset_name = data.get("preset_name")
        source_paths = data.get("source_path")  # Jetzt eine Liste von Pfaden

        if not preset_name or not source_paths or not isinstance(source_paths, list):
            return jsonify({"status": "error", "message": "Preset-Name und gültige Pfade erforderlich!"}), 400

        # Speichern als kommagetrennte Liste
        paths_string = ",".join(source_paths)

        conn = get_db_connection()
        conn.execute("INSERT INTO presets (name, path) VALUES (?, ?)", (preset_name, paths_string))
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": f"Preset {preset_name} gespeichert!"})

    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Preset-Name bereits vergeben!"}), 400


# 🔥 Backup-Preset löschen
@app.route("/delete_preset", methods=["POST"])
def delete_preset():
    try:
        data = request.json
        preset_name = data.get("preset_name")

        conn = get_db_connection()
        conn.execute("DELETE FROM presets WHERE name = ?", (preset_name,))
        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": f"Preset {preset_name} wurde gelöscht!"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# 🔥 Alle Presets anzeigen
@app.route("/list_presets", methods=["GET"])
def list_presets():
    conn = get_db_connection()
    presets = conn.execute("SELECT * FROM presets").fetchall()
    conn.close()

    presets_list = [{"name": row["name"], "path": row["path"]} for row in presets]
    return jsonify({"status": "success", "presets": presets_list})

# 🔥 Backup aus einem Preset starten
@app.route("/backup_preset", methods=["POST"])
def backup_preset():
    """Erstellt ein Backup mit LZMA-Komprimierung basierend auf einem Preset"""
    try:
        data = request.json
        preset_name = data.get("preset_name")

        conn = get_db_connection()
        preset = conn.execute("SELECT path FROM presets WHERE name = ?", (preset_name,)).fetchone()
        conn.close()

        if not preset:
            return jsonify({"status": "error", "message": "Preset nicht gefunden!"}), 404

        source_paths = preset["path"].split(",")
        borg_repo = get_borg_repo()

        # Passphrase & SSH-Passwort aus den Settings abrufen
        with open(SETTINGS_FILE, "r") as file:
            config = json.load(file)
        borg_passphrase = config.get("borg_passphrase", "")
        storage_password = config.get("storage_password", "")

        archive_name = f"{preset_name}-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        # Verwende `sshpass`, um das SSH-Passwort automatisch zu übergeben und LZMA-Kompression zu aktivieren
        cmd = [
            "sshpass", "-p", storage_password,
            "borg", "create", "--lock-wait", "20",
            "--compression", "lzma",  # LZMA-Komprimierung aktivieren
            f"{borg_repo}::{archive_name}"
        ] + source_paths

        # Passphrase übergeben
        subprocess.run(cmd, check=True, env={"BORG_PASSPHRASE": borg_passphrase})

        return jsonify({"status": "success", "message": f"Backup {archive_name} mit LZMA-Komprimierung erstellt (Preset: {preset_name})"})

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": str(e)}), 500




if __name__ == "__main__":
    app.run(host="192.168.178.118", port=5000, debug=True)
