import requests
from requests_oauthlib import OAuth2Session
from urllib.parse import urlparse, parse_qs
from storage import Storage

class TwitterAuth:
    def __init__(self, config):
        self.config = config
        self.storage = Storage()
        self.base_url = "https://api.twitter.com/2"
        
    def generate_auth_url(self):
        """生成带PKCE的认证链接"""
        twitter = OAuth2Session(
            client_id=self.config.twitter_client_id,
            redirect_uri='http://localhost:3000/callback',
            scope=['tweet.read', 'users.read', 'like.read']
        )
        code_verifier = secrets.token_urlsafe(100)
        auth_url = twitter.authorization_url(
            'https://twitter.com/i/oauth2/authorize',
            code_challenge=sha256(code_verifier.encode()).digest(),
            code_challenge_method='S256'
        )
        self.storage.save_pkce(code_verifier)
        return auth_url[0]

    def handle_callback(self, callback_url: str):
        """处理回调并获取token"""
        params = parse_qs(urlparse(callback_url).query)
        code = params.get('code')[0]
        
        twitter = OAuth2Session(client_id=self.config.twitter_client_id)
        token = twitter.fetch_token(
            'https://api.twitter.com/2/oauth2/token',
            code=code,
            code_verifier=self.storage.get_pkce(),
            client_secret=self.config.twitter_client_secret
        )
        self.storage.save_tokens(token)