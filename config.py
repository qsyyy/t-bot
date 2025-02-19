import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

class Config:
    def __init__(self):
        load_dotenv()
        self.fernet = Fernet(os.getenv('ENCRYPTION_KEY'))
        
        # Telegram配置
        self.tg_token = os.getenv('TELEGRAM_TOKEN')
        self.channel_id = os.getenv('TELEGRAM_CHANNEL_ID')
        self.admin_id = os.getenv('TELEGRAM_ADMIN_ID')
        
        # Twitter配置
        self.twitter_client_id = os.getenv('TWITTER_CLIENT_ID')
        self.twitter_client_secret = os.getenv('TWITTER_CLIENT_SECRET')
        self.twitter_uid = os.getenv('TWITTER_UID')
        
    def encrypt_data(self, data: str) -> bytes:
        return self.fernet.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        return self.fernet.decrypt(encrypted_data).decode()