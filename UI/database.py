import sqlite3

# Ensure the database and table exist
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Register a new user
def register_user(username, password):
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        # Check if username exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return False  # Username already exists

        # Insert new user
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return True  # Success

    except sqlite3.Error as e:
        print(f"Database Error: {e}")
        return False

# Call this function when the application starts to initialize the database
init_db()
