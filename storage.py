import sqlite3
from contextlib import contextmanager

class Storage:
    def __init__(self):
        self.conn = sqlite3.connect('bot_data.db')
        self._init_db()
        
    def _init_db(self):
        with self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sync_state (
                id INTEGER PRIMARY KEY,
                last_tweet_id TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            self.conn.execute('''CREATE TABLE IF NOT EXISTS auth_data (
                id INTEGER PRIMARY KEY,
                access_token TEXT,
                refresh_token TEXT,
                expires_at INTEGER
            )''')
    
    @contextmanager
    def get_cursor(self):
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except:
            self.conn.rollback()
            raise
            
    def update_last_id(self, tweet_id: str):
        with self.get_cursor() as c:
            c.execute('''INSERT INTO sync_state (last_tweet_id) 
                      VALUES (?)''', (tweet_id,))