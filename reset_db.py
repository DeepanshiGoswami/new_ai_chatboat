import sqlite3
import uuid
import hashlib
import os

print("🔄 Resetting database with correct schema...")

# Delete old database if exists
if os.path.exists('chatbot.db'):
    os.remove('chatbot.db')
    print("✅ Removed old database")

# Create fresh database
conn = sqlite3.connect('chatbot.db')
cursor = conn.cursor()

# Create tables with correct schema
cursor.executescript('''
    -- Users table with salt column
    CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    );

    -- Sessions table
    CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    );

    -- Chats table
    CREATE TABLE chats (
        chat_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        message_type TEXT,
        content TEXT,
        domain TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    );

    -- Documents table
    CREATE TABLE documents (
        doc_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        file_name TEXT,
        file_type TEXT,
        file_size INTEGER,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        vector_db_reference TEXT,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    );
''')

# Helper function to hash password
def hash_password(password):
    salt = os.urandom(32).hex()
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return password_hash, salt

# Create admin user
admin_id = str(uuid.uuid4())
admin_hash, admin_salt = hash_password("Admin@123")
cursor.execute('''
    INSERT INTO users (user_id, username, email, password_hash, salt, full_name, role)
    VALUES (?, ?, ?, ?, ?, ?, ?)
''', (admin_id, 'admin', 'admin@example.com', admin_hash, admin_salt, 'Administrator', 'admin'))

# Create test user
test_id = str(uuid.uuid4())
test_hash, test_salt = hash_password("Test@123")
cursor.execute('''
    INSERT INTO users (user_id, username, email, password_hash, salt, full_name, role)
    VALUES (?, ?, ?, ?, ?, ?, ?)
''', (test_id, 'test', 'test@example.com', test_hash, test_salt, 'Test User', 'user'))

conn.commit()
conn.close()

print("✅ Database created with correct schema!")
print("📊 Sample users created:")
print("   - Admin: admin / Admin@123")
print("   - Test: test / Test@123")
print("\n🚀 You can now run: streamlit run main.py")