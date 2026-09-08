import sqlite3

print("🔄 Migrating database to add salt column...")

# Connect to database
conn = sqlite3.connect('chatbot.db')
cursor = conn.cursor()

# Check if salt column exists
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
column_names = [col[1] for col in columns]

if 'salt' not in column_names:
    print("📝 Adding salt column to users table...")
    
    # Add salt column
    cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT")
    
    # Generate random salts for existing users
    cursor.execute("SELECT user_id FROM users")
    users = cursor.fetchall()
    
    import os
    for user in users:
        salt = os.urandom(32).hex()
        cursor.execute("UPDATE users SET salt = ? WHERE user_id = ?", (salt, user[0]))
    
    print(f"✅ Added salt to {len(users)} existing users")
else:
    print("✅ salt column already exists")

conn.commit()
conn.close()

print("🎉 Migration complete! You can now run your app.")