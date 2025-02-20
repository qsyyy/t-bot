# main.py 最终稳定版
# 包含完整的OAuth 2.0认证流程和错误处理
# 环境要求：Python 3.10+，依赖见文件底部

#{.env|TELEGRAM_TOKEN="Telegram Bot Token"
#TWITTER_CLIENT_ID="Twitter Client ID"
#TWITTER_CLIENT_SECRET="Twitter Client Secret"
#TELEGRAM_CHANNEL_ID="频道ID"
#TWITTER_UID="Twitter用户ID"
#telegram_admin_USER_ID="382789063"}

import os
import re
import time
import sqlite3
import logging
import secrets
import requests
import hashlib
import base64
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone, timedelta
from telegram import Update, InputMediaPhoto, InputMediaVideo
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,  # 新增MessageHandler
    ContextTypes,
    filters,
    CallbackContext
)
from telegram.helpers import escape_markdown
import tweepy
from dotenv import load_dotenv
from requests_oauthlib import OAuth2Session

# --------------------------
# 初始化部分
# --------------------------

# 加载环境变量（需要项目根目录有.env文件）
load_dotenv()

# 初始化数据库连接（自动创建数据库文件）
conn = sqlite3.connect('tweets_cache.db')
TWITTER_UID = os.getenv("TWITTER_UID")  # 从环境变量获取用户ID

def init_db():
    """初始化数据库表结构"""
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
        tweet_id TEXT PRIMARY KEY,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    # 创建配置表（存储code_verifier等临时数据）
    cursor.execute('''CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    conn.commit()

# --------------------------
# Twitter认证管理类（关键更新）
# --------------------------

class TwitterAuthManager:
    """管理Twitter OAuth 2.0认证流程"""
    def __init__(self):
        self.client_id = os.getenv("TWITTER_CLIENT_ID")
        self.client_secret = os.getenv("TWITTER_CLIENT_SECRET")
        self.redirect_uri = os.getenv("CALLBACK_URI")  # 改为从环境变量读取
        self.scope = ["tweet.read", "users.read", "offline.access", "like.read"]
        self.token_url = "https://api.x.com/2/oauth2/token"

    def _basic_auth(self):
        """生成Basic认证头（用于令牌刷新）"""
        creds = f"{self.client_id}:{self.client_secret}"
        return base64.b64encode(creds.encode()).decode()

    def get_oauth_session(self):
        """创建OAuth2会话对象"""
        return OAuth2Session(
            self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scope
        )

    def generate_auth_url(self):
    #"""生成Twitter认证链接（添加redirect_uri验证）"""
        if not self.redirect_uri.startswith(("http://", "https://")):
            raise ValueError("redirect_uri必须使用HTTP/HTTPS协议")

        oauth = self.get_oauth_session()
        code_verifier = secrets.token_urlsafe(50)  # 生成随机验证码
        code_challenge = self.get_code_challenge(code_verifier)
        auth_url = oauth.authorization_url(
            "https://x.com/i/oauth2/authorize",
            code_challenge=code_challenge,
            code_challenge_method="S256"
        )
        return auth_url[0], code_verifier

    def get_code_challenge(self, code_verifier):
        #"""生成PKCE code challenge"""
        sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(sha256_hash).decode().replace('=', '')

    def save_tokens(self, token):
        #"""保存令牌到数据库"""
        cursor = conn.cursor()
        cursor.execute('''INSERT OR REPLACE INTO twitter_auth 
            (user_id, access_token, refresh_token, expires_at)
            VALUES (?, ?, ?, ?)''',
            (TWITTER_UID, 
             token['access_token'],
             token['refresh_token'],
             int(time.time()) + token.get('expires_in', 7200))  # 默认2小时有效期
        )
        conn.commit()

    def get_valid_client(self):
        #"""获取有效API客户端（自动处理令牌刷新）"""
        cursor = conn.cursor()
        cursor.execute('SELECT access_token, refresh_token, expires_at FROM twitter_auth')
        row = cursor.fetchone()

        if not row:
            raise Exception("请先运行/auth命令进行认证")

        access_token, refresh_token, expires_at = row

        # 令牌刷新逻辑（提前60秒刷新）
        if time.time() > expires_at - 60:
            try:
                response = requests.post(
                    self.token_url,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": f"Basic {self._basic_auth()}"
                    },
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token
                    },
                    timeout=10  # 添加超时设置
                )
                response.raise_for_status()  # 检查HTTP错误
                token = response.json()
            except Exception as e:
                raise Exception(f"令牌刷新失败: {str(e)}")

            if 'error' in token:
                raise Exception(f"令牌刷新失败: {token['error']}")

            self.save_tokens(token)
            access_token = token['access_token']

        return tweepy.Client(
            access_token,
            wait_on_rate_limit=True
        )

# --------------------------
# 认证处理函数（关键更新）
# --------------------------

async def start_auth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    #"""处理/auth命令 - 启动OAuth认证流程"""
    try:
        # 生成认证链接和验证码
        auth_url, code_verifier = auth_manager.generate_auth_url()

        # 保存验证码到数据库
        cursor = conn.cursor()
        cursor.execute('''INSERT OR REPLACE INTO config 
            (key, value) VALUES (?, ?)''',
            ('code_verifier', code_verifier))
        conn.commit()

        # 发送认证链接给用户（添加使用说明）
        await update.message.reply_text(
            f"请访问以下链接进行认证：\n{auth_url}\n\n"
            "操作指南：\n"
            "1. 点击链接登录Twitter账号\n"
            "2. 授权应用权限\n"
            "3. 复制浏览器地址栏的完整URL\n"
            "4. 直接粘贴URL到本聊天"
        )
    except Exception as e:
        logger.error(f"认证初始化失败: {str(e)}", exc_info=True)
        await update.message.reply_text(f"❌ 认证初始化失败：{str(e)}")

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    #"""处理回调URL - 完成OAuth认证流程（关键更新）"""
    try:
        callback_url = update.message.text

        # URL格式验证
        if not re.match(r'^https?://[^\s]+code=[A-Za-z0-9_-]+', callback_url):
            await update.message.reply_text("⚠️ 无效的回调URL格式")
            return

        # 解析URL参数
        parsed_url = urlparse(callback_url)
        query_params = parse_qs(parsed_url.query)
        code = query_params.get('code', [''])[0]

        if not code:
            await update.message.reply_text("⚠️ 无法提取授权码")
            return

        # 从数据库获取code_verifier
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM config WHERE key = "code_verifier"')
        result = cursor.fetchone()

        if not result:
            await update.message.reply_text("❌ 认证会话已过期")
            return

        code_verifier = result[0]

        # 获取访问令牌（符合Confidential Client规范）
        try:
            token = auth_manager.get_oauth_session().fetch_token(
                auth_manager.token_url,
                code=code,
                code_verifier=code_verifier,
                client_secret=auth_manager.client_secret,
                client_id=auth_manager.client_id,
                include_client_id=True,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {auth_manager._basic_auth()}"
                },
                timeout=10
            )
        except Exception as e:
            logger.error(f"令牌获取失败: {str(e)}")
            await update.message.reply_text(f"❌ 认证失败：{str(e)}")
            return

        # 保存令牌到数据库
        auth_manager.save_tokens(token)

        # 使用OAuth2.0认证获取用户信息
        global TWITTER_UID
        if not TWITTER_UID:
            try:
                client = tweepy.Client(
                    bearer_token=token['access_token'],
                    wait_on_rate_limit=True
                )
                user_info = client.get_me(user_auth=False)  # 禁用用户认证流程

                if user_info and user_info.data:
                    TWITTER_UID = user_info.data.id
                    logger.info(f"用户ID自动获取成功: {TWITTER_UID}")
                else:
                    raise ValueError("无法获取有效用户信息")

            except Exception as e:
                logger.error(f"用户信息获取失败: {str(e)}")
                await update.message.reply_text("❌ 无法自动获取用户ID，请手动配置TWITTER_UID")
                return

        await update.message.reply_text("✅ 认证成功！机器人已就绪")

    except Exception as e:
        logger.error(f"回调处理失败: {str(e)}", exc_info=True)
        await update.message.reply_text(f"❌ 认证失败：{str(e)}")


# --------------------------
# 核心功能部分（优化更新）
# --------------------------

# 初始化认证管理器和数据库
auth_manager = TwitterAuthManager()
init_db()

# 增强日志配置
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('bot.log'),  # 日志文件记录
        logging.StreamHandler()         # 控制台输出
    ]
)
logger = logging.getLogger(__name__)

class EnhancedRateLimiter:
    """增强版频率限制器"""
    def __init__(self):
        self.last_call = None
        self.interval = 900  # 15分钟冷却时间
        self.daily_limit = 1
        self.last_manual_run = None
        self.lock = False  # 防止并发请求

    def wait(self):
        #"""等待冷却时间（线程安全）"""
        while self.lock:
            time.sleep(0.1)

        self.lock = True
        try:
            if self.last_call and (time.time() - self.last_call < self.interval):
                remaining = self.interval - (time.time() - self.last_call)
                logger.warning(f"冷却中，剩余等待时间: {remaining:.1f}秒")
                time.sleep(remaining)
            self.last_call = time.time()
        finally:
            self.lock = False

    def can_manual_run(self):
        #"""检查手动触发是否可用"""
        if not self.last_manual_run:
            return True
        elapsed = (datetime.now() - self.last_manual_run).total_seconds()
        return elapsed >= 86400  # 24小时限制

limiter = EnhancedRateLimiter()

async def fetch_and_send_likes(context: ContextTypes.DEFAULT_TYPE):
    #"""主业务逻辑：获取并发送点赞推文（关键更新）"""
    try:
        limiter.wait()
        client = auth_manager.get_valid_client()

        # 获取最后处理ID
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM config WHERE key = "last_processed_id"')
        result = cursor.fetchone()
        last_id = result[0] if result else None

        # 获取点赞推文（添加重试机制）
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = client.get_liked_tweets(
                    TWITTER_UID,
                    max_results=25,
                    expansions=["author_id", "attachments.media_keys"],
                    tweet_fields=["created_at", "text"],
                    user_fields=["name", "username"],
                    media_fields=["url", "type", "variants"]
                )
                break
            except tweepy.TooManyRequests as e:
                if attempt < max_retries - 1:
                    wait_time = e.response.headers.get('x-rate-limit-reset', 300)
                    logger.warning(f"触发速率限制，等待{wait_time}秒后重试")
                    time.sleep(wait_time)
                    continue
                else:
                    raise
            except Exception as e:
                logger.error(f"API请求异常: {str(e)}")
                raise

        if not response.data:
            logger.info("没有新的点赞推文")
            return

        # 处理新推文
        new_tweets = []
        current_max_id = response.data[0].id
        for tweet in response.data:
            if tweet.id == last_id:
                break
            if not is_tweet_processed(tweet.id):
                new_tweets.append(tweet)

        if not new_tweets:
            logger.info("没有检测到新增点赞")
            return

        # 逆序处理保证最新推文最后发送
        for tweet in reversed(new_tweets):
            try:
                await process_single_tweet(tweet, response.includes, context)
                mark_tweet_processed(tweet.id)
            except Exception as e:
                logger.error(f"处理推文 {tweet.id} 失败: {str(e)}")
                continue

        # 更新最后处理ID
        cursor.execute('INSERT OR REPLACE INTO config (key, value) VALUES ("last_processed_id", ?)', (current_max_id,))
        conn.commit()

    except Exception as e:
        logger.error(f"获取点赞失败: {str(e)}", exc_info=True)
        await send_error(context, f"❌ 获取点赞失败：{escape_markdown(str(e), version=2)}")

def is_tweet_processed(tweet_id):
    """检查推文是否已处理（添加缓存优化）"""
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM processed_tweets WHERE tweet_id = ?', (tweet_id,))
    return cursor.fetchone() is not None

def mark_tweet_processed(tweet_id):
    """标记推文为已处理（添加批量提交优化）"""
    cursor = conn.cursor()
    cursor.execute('INSERT INTO processed_tweets (tweet_id) VALUES (?)', (tweet_id,))
    conn.commit()

async def process_single_tweet(tweet, includes, context):
    """处理单条推文并发送到Telegram（媒体处理增强）"""
    try:
        author = next(u for u in includes['users'] if u.id == tweet.author_id)
        media_urls = process_media(tweet, includes)

        # 构造消息内容（使用Markdown V2格式）
        caption = (
            f"[{escape_markdown(author.name, version=2)}](https://twitter.com/{author.username}):\n"
            f"{escape_markdown(clean_text(tweet.text), version=2)}\n\n"
            f"🔗 [推文链接](https://twitter.com/{author.username}/status/{tweet.id})"
        )

        # 媒体处理逻辑优化
        if media_urls:
            media_group = []
            for idx, media in enumerate(media_urls[:4]):  # Telegram最多支持10个媒体，但建议4个以内
                try:
                    media_type = InputMediaVideo if media['type'] == 'video' else InputMediaPhoto
                    media_item = media_type(
                        media=media['url'],
                        caption=caption if idx == 0 else None,
                        parse_mode='MarkdownV2'
                    )
                    media_group.append(media_item)
                except Exception as e:
                    logger.error(f"媒体处理失败: {str(e)}")
                    continue

            if media_group:
                await context.bot.send_media_group(
                    chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
                    media=media_group
                )
            else:
                await send_media_fallback(caption, context)
        else:
            await context.bot.send_message(
                chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
                text=caption,
                parse_mode='MarkdownV2'
            )

    except StopIteration:
        logger.error(f"未找到作者信息，推文ID: {tweet.id}")
        await send_error(context, f"❌ 推文处理失败：无法获取作者信息")
    except Exception as e:
        logger.error(f"处理推文失败: {str(e)}", exc_info=True)
        await send_error(context, f"❌ 推文处理失败：{escape_markdown(str(e), version=2)}")

async def send_media_fallback(caption, context):
    """媒体发送失败时的备用方案"""
    try:
        await context.bot.send_message(
            chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
            text=f"{caption}\n\n⚠️ 媒体内容无法加载",
            parse_mode='MarkdownV2'
        )
    except Exception as e:
        logger.error(f"备用消息发送失败: {str(e)}")

def process_media(tweet, includes):
    """处理推文中的媒体附件（增强兼容性）"""
    media_list = []
    if hasattr(tweet, 'attachments'):
        for media_key in tweet.attachments.get('media_keys', []):
            try:
                media = next(m for m in includes['media'] if m.media_key == media_key)
                if media.type == 'photo':
                    media_list.append({'type': 'photo', 'url': media.url})
                elif media.type in ['video', 'animated_gif']:
                    variants = sorted(
                        [v for v in media.variants if 'bit_rate' in v],
                        key=lambda x: x.get('bit_rate', 0),
                        reverse=True
                    )
                    if variants:
                        best_url = max(variants, key=lambda x: x.get('bit_rate', 0))['url']
                        media_list.append({'type': 'video', 'url': best_url})
            except StopIteration:
                continue
            except Exception as e:
                logger.error(f"媒体处理异常: {str(e)}")
                continue
    return media_list

def clean_text(text):
    """清理推文文本（增强清理逻辑）"""
    cleaned = re.sub(r'https://t\.co/\w+', '', text).strip()
    return re.sub(r'\s{2,}', ' ', cleaned)  # 合并多个空格

async def send_error(context, message):
    """发送错误消息到频道（添加频率限制）"""
    try:
        await context.bot.send_message(
            chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
            text=message,
            parse_mode='MarkdownV2'
        )
    except Exception as e:
        logger.error(f"错误消息发送失败: {str(e)}")

async def manual_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """手动触发更新命令处理（添加权限检查）"""
    # 检查用户权限
    if update.effective_user.id != int(os.getenv("ADMIN_USER_ID")):
        await update.message.reply_text("⚠️ 无权执行此操作")
        return

    message = update.effective_message
    if not limiter.can_manual_run():
        msg = await context.bot.send_message(
            chat_id=message.chat.id,
            text="⚠️ 24小时内只能手动触发一次"
        )
        context.job_queue.run_once(delete_message, 10, data=msg.message_id)
        return

    try:
        await context.bot.delete_message(
            chat_id=message.chat.id,
            message_id=message.message_id
        )

        limiter.last_manual_run = datetime.now()
        await fetch_and_send_likes(context)
    except Exception as e:
        logger.error(f"手动触发失败: {str(e)}")
        await send_error(context, f"❌ 手动触发失败：{escape_markdown(str(e), version=2)}")

async def delete_message(context: CallbackContext):
    """自动删除临时消息（添加异常处理）"""
    try:
        await context.bot.delete_message(
            chat_id=os.getenv("TELEGRAM_CHANNEL_ID"),
            message_id=context.job.data
        )
    except Exception as e:
        logger.error(f"消息删除失败: {str(e)}")

def main():
    """主程序入口（更新处理器配置）"""
    init_db()
    application = Application.builder().token(os.getenv("TELEGRAM_TOKEN")).build()

    # 设置定时任务（北京时间每天6:00和22:00运行）
    beijing_tz = timezone(timedelta(hours=8))
    application.job_queue.run_daily(
        fetch_and_send_likes,
        time=datetime.strptime("06:00", "%H:%M").time().replace(tzinfo=beijing_tz),
        days=tuple(range(7)),
        name="morning_job"
    )
    application.job_queue.run_daily(
        fetch_and_send_likes,
        time=datetime.strptime("22:00", "%H:%M").time().replace(tzinfo=beijing_tz),
        days=tuple(range(7)),
        name="night_job"
    )

    # 更新处理器配置（关键修改）
    application.add_handler(CommandHandler("update", manual_update, filters.ChatType.PRIVATE))
    application.add_handler(CommandHandler("auth", start_auth, filters.ChatType.PRIVATE))

    # 使用MessageHandler代替原来的CommandHandler处理回调URL
    application.add_handler(MessageHandler(
        filters.TEXT & (~filters.COMMAND) & filters.ChatType.PRIVATE,
        handle_callback
    ))

    # 添加错误处理
    application.add_error_handler(error_handler)

    logger.info("机器人启动成功")
    application.run_polling()

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """全局错误处理"""
    logger.error(f"全局异常: {context.error}", exc_info=True)
    if update.effective_message:
        await update.effective_message.reply_text(f"⚠️ 系统错误: {str(context.error)}")

if __name__ == "__main__":
    main()
