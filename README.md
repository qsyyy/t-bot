项目实现了：

-绑定推特账号和telegram的频道。
-使用免费推特api
-支持手动拉取点赞和自动定时拉取。
-在频道中发送/update 手动触发拉取
-可指定默认拉取的推文数 


项目环境需要：
	# .env
TELEGRAM_TOKEN=
TWITTER_BEARER_TOKEN=
TELEGRAM_CHANNEL_ID=
TWITTER_CLIENT_ID=
TWITTER_CLIENT_SECRET=
	
请确保在Twitter开发者门户创建应用时选择OAuth 2.0类型，并正确配置回调地址为
http://localhost:3000/callback


! 重要设置检查清单
	√ 服务器时区设置为本地时区（影响定时任务执行时间）
	√ Bot在频道有删除消息权限（需设置为管理员）
	√ Twitter API权限包含tweet.read和users.read
	√ 确保网络可访问api.twitter.com


初次运行准备步骤：

	pip install -r requirements.txt

# 创建并初始化数据库
python -c "import sqlite3; conn = sqlite3.connect('tweets_cache.db'); conn.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)'); conn.execute('CREATE TABLE IF NOT EXISTS processed_tweets (tweet_id TEXT PRIMARY KEY)'); conn.commit()"

# 测试数据库写入权限
python -c "import sqlite3; conn = sqlite3.connect('tweets_cache.db'); conn.execute('INSERT INTO config (key, value) VALUES (\"test\", \"123\")'); conn.commit()"

然后：python main.py
