import sqlite3

conn = sqlite3.connect('cloud_storage.db')
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

print("users Table:")
for row in rows:
    print(row)

conn.close()
