from telegram import Bot, InputMediaPhoto, InputMediaVideo
from telegram.error import TelegramError

class TelegramClient:
    def __init__(self, config):
        self.bot = Bot(token=config.tg_token)
        self.channel_id = config.channel_id
    
    def _build_message(self, tweet: Dict) -> Dict:
        """构造消息结构"""
        return {
            'text': f"[{tweet['author_name']}]({tweet['author_url']}):\n\n"
                    f"{tweet['text']}\n\n"
                    f"🔗 [原文链接]({tweet['url']})",
            'media': tweet.get('media', []),
            'entities': [
                {
                    'type': 'text_link',
                    'offset': 0,
                    'length': len(tweet['author_name'])+1,
                    'url': tweet['author_url']
                }
            ]
        }
    
    async def send_to_channel(self, tweet: Dict):
        """发送消息到频道"""
        try:
            message = self._build_message(tweet)
            
            if message['media']:
                media_group = [
                    InputMediaVideo(media=url) if url.endswith('.mp4') 
                    else InputMediaPhoto(media=url)
                    for url in message['media']
                ]
                await self.bot.send_media_group(
                    chat_id=self.channel_id,
                    media=media_group
                )
            
            await self.bot.send_message(
                chat_id=self.channel_id,
                text=message['text'],
                entities=message['entities'],
                disable_web_page_preview=True
            )
        except TelegramError as e:
            self.logger.error(f"Telegram发送失败: {e}")