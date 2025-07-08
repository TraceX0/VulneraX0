import sqlite3
conn = sqlite3.connect('database.db')
c = conn.cursor()
c.execute('DELETE FROM comments')
c.execute("INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)", ('Virat', 'Great fintech platform! Easy to use and secure.', '2025-07-04 12:31:21'))
c.execute("INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)", ('Hardik', 'I love the fast transfers and support.', '2025-07-05 09:15:00'))
c.execute("INSERT INTO comments (name, content, timestamp) VALUES (?, ?, ?)", ('Shubhman', 'The UI is clean and modern. Well done!', '2025-07-06 10:00:00'))
c.execute('''
CREATE TABLE IF NOT EXISTS daily_limits (
    user_id INTEGER PRIMARY KEY,
    amount_sent_today INTEGER,
    last_reset TEXT
)
''')
conn.commit()
conn.close()
print("Default comments set.")
print("daily_limits table created.")