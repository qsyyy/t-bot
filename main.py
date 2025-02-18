import os
import re
import time
import json
import sqlite3
import logging
from telegram import Update, InputMediaPhoto, InputMediaVideo
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from telegram.helpers import escape_markdown
import tweepy
from dotenv import load_dotenv

load_dotenv()

# 初始化数据库
conn = sqlite3.connect('tweets_cache.db')

def init_db():
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tweets (
            tweet_id TEXT PRIMARY KEY,
            images TEXT,
            caption TEXT,
            created_at TIMESTAMP
        )
    ''')
    conn.commit()

def get_cached_tweet(tweet_id):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT images, caption FROM tweets 
        WHERE tweet_id = ? AND created_at > datetime('now', '-1 hour')
    ''', (tweet_id,))
    row = cursor.fetchone()
    return json.loads(row[0]) if row else None

def cache_tweet(tweet_id, data):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO tweets 
        (tweet_id, images, caption, created_at)
        VALUES (?, ?, ?, datetime('now'))
    ''', (tweet_id, json.dumps(data['images']), data['caption']))
    conn.commit()

# Twitter客户端配置
client = tweepy.Client(bearer_token=os.getenv("TWITTER_BEARER_TOKEN"))

class TwitterRateLimiter:
    def __init__(self):
        self.last_call = None
        self.interval = 1.5
    
    def wait(self):
        if self.last_call:
            elapsed = time.time() - self.last_call
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
        self.last_call = time.time()

limiter = TwitterRateLimiter()

# 日志配置
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

async def process_tweet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.channel_post
    if not message or not message.text:
        return

    urls = list(set(re.findall(r'https?://(?:twitter\.com|x\.com)/\w+/status/(\d+)', message.text)))
    if not urls:
        return

    try:
        processed = False
        for url in urls:
            limiter.wait()
            tweet_id = url
            
            # 尝试获取缓存
            cached = get_cached_tweet(tweet_id)
            if cached:
                media_urls = cached['images']
                caption = cached['caption']
            else:
                # 调用Twitter API
                tweet = client.get_tweet(
                    tweet_id,
                    expansions=["author_id", "attachments.media_keys"],
                    tweet_fields=["text"],
                    user_fields=["name", "username"],
                    media_fields=["url", "type", "variants"]
                )
                
                # 处理用户信息
                author = tweet.includes['users'][0]
                author_name = escape_markdown(author.name, version=2)
                author_link = f"[{author_name}](https://twitter.com/{author.username})"
                
                # 处理媒体内容
                media_urls = []
                if 'media' in tweet.includes:
                    for media in tweet.includes['media']:
                        media_info = None
                        if media.type == 'photo':
                            media_info = {'type': 'photo', 'url': media.url}
                        elif media.type == 'video':
                            variants = [v for v in media.variants if 'bit_rate' in v]
                            if variants:
                                best_variant = max(variants, key=lambda x: x.get('bit_rate', 0))
                                media_info = {'type': 'video', 'url': best_variant['url']}
                        elif media.type == 'animated_gif':
                            variants = media.variants
                            if variants:
                                mp4_variant = next((v for v in variants if v.get('content_type') == 'video/mp4'), None)
                                if mp4_variant:
                                    media_info = {'type': 'video', 'url': mp4_variant['url']}
                        if media_info:
                            media_urls.append(media_info)
                
                # 处理推文文本
                text = re.sub(r'https://t\.co/\w+', '', tweet.data.text).strip()
                text = escape_markdown(text, version=2)
                
                # 构建消息内容
                caption = (
                    f"{author_link}:\n"
                    f"{text}\n\n"
                    f"🔗 [source](https://twitter.com/{author.username}/status/{tweet_id})"
                )
                
                # 缓存数据
                cache_tweet(tweet_id, {'images': media_urls, 'caption': caption})
            
            # 发送消息
            if media_urls:
                media_group = []
                for idx, media_info in enumerate(media_urls):
                    media_type = media_info['type']
                    url = media_info['url']
                    media_class = InputMediaPhoto if media_type == 'photo' else InputMediaVideo
                    
                    if idx == 0:
                        media = media_class(media=url, caption=caption, parse_mode='MarkdownV2')
                    else:
                        media = media_class(media=url)
                    media_group.append(media)
                
                await context.bot.send_media_group(
                    chat_id=message.chat_id,
                    media=media_group
                )
            else:
                await context.bot.send_message(
                    chat_id=message.chat_id,
                    text=caption,
                    parse_mode='MarkdownV2'
                )
            
            processed = True
        
        # 删除原始消息
        if processed:
            await context.bot.delete_message(
                chat_id=message.chat_id,
                message_id=message.message_id
            )
    
    except Exception as e:
        logger.error(f"处理失败: {str(e)}", exc_info=True)
        error_message = escape_markdown(f"❌ 处理失败：{str(e)}", version=2)
        await context.bot.send_message(
            chat_id=message.chat_id,
 text=error_message,
            parse_mode='MarkdownV2'
        )
        try:
            await context.bot.delete_message(
                chat_id=message.chat_id,
                message_id=message.message_id
            )
        except Exception as delete_error:
            logger.error(f"删除消息失败: {str(delete_error)}")

def main():
    init_db()
    application = Application.builder().token(os.getenv("TELEGRAM_TOKEN")).build()
    application.add_handler(MessageHandler(filters.TEXT & filters.ChatType.CHANNEL, process_tweet))
    application.run_polling()

if __name__ == "__main__":
    main()