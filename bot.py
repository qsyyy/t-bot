from apscheduler.schedulers.asyncio import AsyncIOScheduler
from telegram.ext import Application

class SyncBot:
    def __init__(self):
        self.config = Config()
        self.storage = Storage()
        self.scheduler = AsyncIOScheduler()
        self.tg_app = Application.builder().token(self.config.tg_token).build()
        
    async def sync_job(self):
        """核心同步任务"""
        try:
            # 获取最新点赞
            tweets = await TwitterAPI(self.config).get_likes(
                self.storage.last_id
            )
            
            # 处理数据
            new_tweets = DataProcessor(self.storage).process(tweets)
            
            # 发送到Telegram
            for tweet in new_tweets:
                await TelegramClient(self.config).send_to_channel(tweet)
                
            # 更新存储
            self.storage.update_last_id(tweets[-1]['id'])
            
        except APIQuotaExceeded:
            await self.notify_admin("API限额已用尽，本月剩余同步已禁用")
            self.scheduler.pause()
            
    def run(self):
        # 设置定时任务
        self.scheduler.add_job(
            self.sync_job, 
            'cron', 
            hour='6,22', 
            timezone='UTC'
        )
        
        # 注册命令处理器
        self.tg_app.add_handler(
            CommandHandler('update', self.manual_trigger)
        self.tg_app.add_handler(
            CommandHandler('auth', self.handle_auth))
        
        # 启动服务
        self.scheduler.start()
        self.tg_app.run_polling()