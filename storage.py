import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).with_name("lab.db")


def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = connect()
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        DROP TABLE IF EXISTS coupons;
        DROP TABLE IF EXISTS audit_events;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_plain TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL
        );

        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );

        CREATE TABLE coupons (
            code TEXT PRIMARY KEY,
            discount INTEGER NOT NULL,
            max_uses INTEGER NOT NULL,
            uses INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    users = [
        (1, "alice", "alice123", generate_password_hash("alice123"), "user", "alice@lab.local"),
        (2, "bob", "bob123", generate_password_hash("bob123"), "user", "bob@lab.local"),
        (3, "admin", "admin123", generate_password_hash("admin123"), "admin", "admin@lab.local"),
    ]
    db.executemany(
        "INSERT INTO users(id, username, password_plain, password_hash, role, email) VALUES(?,?,?,?,?,?)",
        users,
    )

    notes = [
        (1, 1, "Alice - anotação privada", "Token fictício de laboratório: ALICE-DEMO-001"),
        (2, 2, "Bob - anotação privada", "Somente Bob deveria conseguir visualizar esta nota."),
        (3, 3, "Admin - checklist", "Revisar controles de autorização antes do go-live."),
    ]
    db.executemany("INSERT INTO notes(id, owner_id, title, body) VALUES(?,?,?,?)", notes)

    db.executemany(
        "INSERT INTO coupons(code, discount, max_uses, uses) VALUES(?,?,?,?)",
        [("WELCOME50", 50, 1, 0), ("STUDENT20", 20, 3, 0)],
    )
    db.commit()
    db.close()
