import sqlite3
import pandas as pd

# Connect to database
conn = sqlite3.connect('chatbot.db')

# Check all users
print("👥 Registered Users:")
users_df = pd.read_sql_query("SELECT user_id, username, email FROM users", conn)
print(users_df)
print("\n" + "="*50)

# Pick a user to check their chats
user_id = input("Enter user_id from above: ")

# Get all chats for that user
chats_df = pd.read_sql_query(f"""
    SELECT message_type, content, domain, timestamp 
    FROM chats 
    WHERE user_id = '{user_id}'
    ORDER BY timestamp DESC
""", conn)

print(f"\n💬 Chat History for User {user_id}:")
print(chats_df)

conn.close()