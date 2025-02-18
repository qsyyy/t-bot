import os
import re
import time
import sqlite3
import logging
import secrets
import requests
from datetime import datetime, timezone, timedelta
from telegram import Update, InputMediaPhoto, InputMediaVideo
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    filters,
    CallbackContext
)
from telegram.helpers import escape_markdown
import tweepy
from dotenv import load_dotenv
from requests_oauthlib import OAuth2Session

# 加载环境变量
load_dotenv()

# 初始化数据库
conn = sqlite3.connect('tweets_cache.db')
TWITTER_UID = "887176491200466944"

def init_db():
    cursor = conn.cursor()
    # 创建认证信息表
    cursor.execute('''CREATE TABLE IF NOT EXISTS twitter_auth (
        user_id TEXT PRIMARY KEY,
        access_token TEXT,
        refresh_token TEXT,
        expires_at INTEGER
    )''')
    # 创建已处理推文表
    cursor.execute('''CREATE TABLE IF NOT EXISTS processed_tweets (
        tweet_id TEXT PRIMARY KEY
    )''')
    conn.commit()

class TwitterAuthManager:
    def __init__(self):
        self.client_id = os.getenv("TWITTER_CLIENT_ID")
        self.client_secret = os.getenv("TWITTER_CLIENT_SECRET")
        self.redirect_uri = "http://localhost:3000/callback"
        self.scope = ["tweet.read", "users.read", "offline.access"]

    def get_oauth_session(self):
        return OAuth2Session(
            self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scope
        )

    def generate_auth_url(self):
        """生成Twitter认证链接"""
        oauth = self.get_oauth_session()
        code_verifier = secrets.token_urlsafe(50)
        code_challenge = self.get_code_challenge(code_verifier)  # 新增方法
        auth_url = oauth.authorization_url(
            "https://twitter.com/i/oauth2/authorize",
            code_challenge=code_challenge,
            code_challenge_method="S256"
        )
        return auth_url[0], code_verifier

# 新增方法：生成符合PKCE规范的code_challenge
    def get_code_challenge(self, code_verifier):
        import hashlib, base64
        code_verifier_bytes = code_verifier.encode('utf-8')
        sha256_hash = hashlib.sha256(code_verifier_bytes).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').replace('=', '')
        return code_challenge
    def save_tokens(self, token):
        """保存令牌到数据库"""
        cursor = conn.cursor()
        cursor.execute('''INSERT OR REPLACE INTO twitter_auth 
            (user_id, access_token, refresh_token, expires_at)
            VALUES (?, ?, ?, ?)''',
            (TWITTER_UID, 
             token['access_token'],
             token['refresh_token'],
             int(time.time()) + token['expires_in'])
        )
        conn.commit()

    def get_valid_client(self):
        """获取有效客户端并自动刷新令牌"""
        cursor = conn.cursor()
        cursor.execute('SELECT access_token, refresh_token, expires_at FROM twitter_auth')
        row = cursor.fetchone()

        if not row:
            raise Exception("未找到有效认证信息，请先运行/auth命令认证")

        access_token, refresh_token, expires_at = row

        # 检查令牌是否过期
        if time.time() > expires_at - 60:
            token = requests.post(
                "https://api.twitter.com/2/oauth2/token",
                auth=(self.client_id, self.client_secret),
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token
                }
            ).json()

            self.save_tokens(token)
            access_token = token['access_token']

        return tweepy.Client(
            access_token,
            wait_on_rate_limit=True
        )

# 初始化认证管理器和数据库
auth_manager = TwitterAuthManager()
init_db()

# 日志配置
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self):
        self.last_call = None
        self.interval = 4
        self.daily_limit = 1
        self.last_manual_run = None

    def wait(self):
        if self.last_call and (time.time() - self.last_call < self.interval):
            time.sleep(self.interval - (time.time() - self.last_call))
        self.last_call = time.time()

    def can_manual_run(self):
        if not self.last_manual_run:
            return True
        return (datetime.now() - self.last_manual_run).total_seconds() >= 86400

limiter = RateLimiter()

async def fetch_and_send_likes(context: ContextTypes.DEFAULT_TYPE):
    try:
        limiter.wait()
        client = auth_manager.get_valid_client()

        # 获取最后处理ID
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM config WHERE key = "last_processed_id"')
        last_id = cursor.fetchone()[0] if cursor.fetchone() else None

        # 获取点赞推文
        response = client.get_liked_tweets(
            TWITTER_UID,
            max_results=100,
            expansions=["author_id", "attachments.media_keys"],
            tweet_fields=["created_at", "text"],
            user_fields=["name", "username"],
            media_fields=["url", "type", "variants"]
        )

        if not response.data:
            return

        new_tweets = []
        current_max_id = response.data[0].id
        for tweet in response.data:
            if tweet.id == last_id:
                break
            cursor.execute('SELECT 1 FROM processed_tweets WHERE tweet_id = ?', (tweet.id,))
            if not cursor.fetchone():
                new_tweets.append(tweet)

        if not new_tweets:
            return

        # 逆序处理推文
        for tweet in reversed(new_tweets):
            await process_single_tweet(tweet, response.includes, context)
            cursor.execute('INSERT INTO processed_tweets (tweet_id) VALUES (?)', (tweet.id,))

        # 更新最后处理ID
        cursor.execute('INSERT OR REPLACE INTO config (key, value) VALUES ("last_processed_id", ?)', (current_max_id,))
        conn.commit()

    except Exception as e:
        logger.error(f"获取点赞失败: {str(e)}", exc_info=True)
        await send_error(context, f"❌ 获取点赞失败：{str(e)}")

async def process_single_tweet(tweet, includes, context):
    try:
        author = next(u for u in includes['users'] if u.id == tweet.author_id)
        author_name = escape_markdown(author.name, version=2)
        author_link = f"[{author_name}](https://twitter.com/{author.username})"

        media_urls = []
        if 'media' in includes:
            media_list = [m for m in includes['media'] if m.media_key in tweet.attachments['media_keys']]
            for media in media_list:
                if media.type == 'photo':
                    media_urls.append({'type': 'photo', 'url': media.url})
                elif media.type in ['video', 'animated_gif']:
                    variants = sorted(
                        [v for v in media.variants if 'bit_rate' in v],
                        key=lambda x: x.get('bit_rate', 0),
                        reverse=True
                    )
                    if variants:
                        media_urls.append({'type': 'video', 'url': variants[0]['url']})

        text = re.sub(r'https://t\.co/\w+', '', tweet.text).strip()
        text = escape_markdown(text, version=2)

        caption = (
            f"{author_link}:\n"
            f"{text}\n\n"
            f"🔗 [来源](https://twitter.com/{author.username}/status/{tweet.id})"
        )

        if media_urls:
            media_group = []
            for idx, media_info in enumerate(media_urls[:4]):
                media_class = InputMediaPhoto if media_info['type'] == 'photo' else InputMediaVideo
                media = media_class(
                    media=media_info['url'],
                    caption=caption if idx == 0 else None,
                    parse_mode='MarkdownV2'
                )
                media_group.append(media)

            await context.bot.send_media_group(
                chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
                media=media_group
            )
        else:
            await context.bot.send_message(
                chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
                text=caption,
                parse_mode='MarkdownV2'
            )

    except Exception as e:
        logger.error(f"处理推文失败: {str(e)}", exc_info=True)
        await send_error(context, f"❌ 处理推文失败：{str(e)}")

async def send_error(context, message):
    await context.bot.send_message(
        chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
        text=escape_markdown(message, version=2),
        parse_mode='MarkdownV2'
    )

async def manual_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.channel_post or update.message
    if not message:
        logger.error("无法获取消息对象")
        return

    if not limiter.can_manual_run():
        msg = await context.bot.send_message(
            chat_id=message.chat.id,
            text="⚠️ 24小时内只能手动触发一次"
        )
        context.job_queue.run_once(delete_message, 5, data=msg.message_id)
        return

    try:
        limiter.last_manual_run = datetime.now()
        await context.bot.delete_message(
            chat_id=message.chat.id,
            message_id=message.message_id
        )
        await fetch_and_send_likes(context)
    except Exception as e:
        logger.error(f"手动触发失败: {str(e)}")
        await send_error(context, f"❌ 手动触发失败：{str(e)}")

async def start_auth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """启动Twitter认证流程"""
    auth_url, code_verifier = auth_manager.generate_auth_url()
    context.user_data['code_verifier'] = code_verifier
    await update.message.reply_text(
        f"请访问以下链接完成Twitter认证：\n{auth_url}\n"
        "认证完成后，请将回调URL中的code参数发送给我（格式：/callback <code>）"
    )

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理回调code"""
    code = update.message.text.split()[-1]
    code_verifier = context.user_data.get('code_verifier')

    try:
        # 调试日志输出关键参数
        logger.info(f"尝试认证参数: client_id={auth_manager.client_id[:5]}..., client_secret={auth_manager.client_secret[:5]}...")

        # 显式构建认证头
        auth = (auth_manager.client_id, auth_manager.client_secret)

        # 获取令牌并包含所有必要参数
        token = auth_manager.get_oauth_session().fetch_token(
            "https://api.twitter.com/2/oauth2/token",
            code=code,
            code_verifier=code_verifier,
            client_id=auth_manager.client_id,
            client_secret=auth_manager.client_secret,
            auth=auth,  # 显式添加基础认证
            include_client_id=True,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {auth_manager._basic_auth()}"  # 新增基础认证方法
            }
        )

        # 验证令牌结构
        if 'access_token' not in token:
            raise ValueError("Invalid token response")

        auth_manager.save_tokens(token)
        await update.message.reply_text("✅ 认证成功！现在可以使用/update命令了")
        logger.info("认证成功，令牌已保存")

    except Exception as e:
        error_msg = f"❌ 认证失败：{str(e)}"
        logger.error(f"认证失败详情: {error_msg}", exc_info=True)
        await update.message.reply_text(error_msg)
        token = None  # 确保变量已定义

async def delete_message(context: CallbackContext):
    await context.bot.delete_message(
        chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
        message_id=context.job.data
    )

def main():
    init_db()
    application = Application.builder().token(os.getenv("TELEGRAM_TOKEN")).build()

    # 设置定时任务
    if application.job_queue:
        beijing_tz = timezone(timedelta(hours=8))
        application.job_queue.run_daily(
            fetch_and_send_likes,
            time=datetime.strptime("06:00", "%H:%M").time().replace(tzinfo=beijing_tz),
            days=tuple(range(7)),
        )
        application.job_queue.run_daily(
            fetch_and_send_likes,
            time=datetime.strptime("22:00", "%H:%M").time().replace(tzinfo=beijing_tz),
            days=tuple(range(7)),
        )
    else:
        logger.warning("定时任务不可用")




    # 添加命令处理器
    application.add_handler(CommandHandler("update", manual_update, filters.ChatType.CHANNEL))
    application.add_handler(CommandHandler("auth", start_auth))
    application.add_handler(CommandHandler("callback", handle_callback))

    application.run_polling()




















if __name__ == "__main__":
    main()
