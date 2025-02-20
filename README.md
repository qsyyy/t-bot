
-绑定推特账号和telegram的频道。
-使用免费推特api
-北京时间6:00和22:00定时执行。
-在频道或者私聊bot发送/update 手动触发
-可指定默认拉取的推文数 


项目环境需要：
#.env 示例
TELEGRAM_TOKEN="你的Telegram Bot Token"
TWITTER_CLIENT_ID="你的Twitter Client ID"
TWITTER_CLIENT_SECRET="你的Twitter Client Secret"
TELEGRAM_CHANNEL_ID="你的频道ID"
TWITTER_UID="你的Twitter用户ID"


	
请确保在Twitter开发者门户创建应用时选择OAuth 2.0类型，并正确配置回调地址为
http://localhost:3000/callback




初始化：


# 安装依赖
pip install -r requirements.txt

然后：python main.py
