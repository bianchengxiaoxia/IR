# Scrapy settings for NANKAIIR project
#
# For simplicity, this file contains only settings considered important or
# commonly used. You can find more settings consulting the documentation:
#
#     https://docs.scrapy.org/en/latest/topics/settings.html
#     https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
#     https://docs.scrapy.org/en/latest/topics/spider-middleware.html

BOT_NAME = "NANKAIIR"

SPIDER_MODULES = ["NANKAIIR.spiders"]
NEWSPIDER_MODULE = "NANKAIIR.spiders"


# Crawl responsibly by identifying yourself (and your website) on the user-agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"

# Obey robots.txt rules
ROBOTSTXT_OBEY = True

# Configure maximum concurrent requests performed by Scrapy (default: 16)
CONCURRENT_REQUESTS = 16
DEPTH_LIMIT = 8 # 限制爬取深度为 3
# 移除504状态码，使其不再被重试
RETRY_HTTP_CODES = [500, 503,522, 524, 408]

# 保持重试功能开启
RETRY_ENABLED = True

# 设置重试次数
RETRY_TIMES = 5  # 根据需要调整

# 设置下载超时时间（可选）
DOWNLOAD_TIMEOUT = 30  # 秒

# 允许特定状态码通过，不抛出异常
# 例如，302（重定向）和404（未找到）

# 启用自定义下载中间件
DOWNLOADER_MIDDLEWARES = {
    # 保持 Scrapy 默认中间件的优先级
    'scrapy.downloadermiddlewares.retry.RetryMiddleware': 90,
    'scrapy.downloadermiddlewares.redirect.RedirectMiddleware': 600,
    'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 750,
    'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': 400,

    # 添加自定义的 Handle504Middleware
    'NANKAIIR.middlewares.Handle504Middleware': 100,  # 替换为您的项目名称
}

# Configure a delay for requests for the same website (default: 0)
# See https://docs.scrapy.org/en/latest/topics/settings.html#download-delay
# See also autothrottle settings and docs
DOWNLOAD_DELAY = 0.1
# The download delay setting will honor only one of:
#CONCURRENT_REQUESTS_PER_DOMAIN = 16
#CONCURRENT_REQUESTS_PER_IP = 16
# 启用自动限速（AutoThrottle）
AUTOTHROTTLE_ENABLED = True
# 初始下载延迟，可以视情况略微降低
AUTOTHROTTLE_START_DELAY = 0.5
# 在高延迟情况下的最大下载延迟，保持为默认或适当调低
AUTOTHROTTLE_MAX_DELAY = 5
# 目标并发请求数，越高爬得越快，但压力也越大，根据情况调整
AUTOTHROTTLE_TARGET_CONCURRENCY = 4.0
# 输出autothrottle调试信息（可选）
AUTOTHROTTLE_DEBUG = False
# Disable cookies (enabled by default)
#COOKIES_ENABLED = False

# Disable Telnet Console (enabled by default)
#TELNETCONSOLE_ENABLED = False

# Override the default request headers:
#DEFAULT_REQUEST_HEADERS = {
#    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#    "Accept-Language": "en",
#}

# Enable or disable spider middlewares
# See https://docs.scrapy.org/en/latest/topics/spider-middleware.html
#SPIDER_MIDDLEWARES = {
#    "NANKAIIR.middlewares.NankaiirSpiderMiddleware": 543,
#}

# Enable or disable downloader middlewares
# See https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
#DOWNLOADER_MIDDLEWARES = {
#    "NANKAIIR.middlewares.NankaiirDownloaderMiddleware": 543,
#}

# Enable or disable extensions
# See https://docs.scrapy.org/en/latest/topics/extensions.html
#EXTENSIONS = {
#    "scrapy.extensions.telnet.TelnetConsole": None,
#}

# Configure item pipelines
# See https://docs.scrapy.org/en/latest/topics/item-pipeline.html
#ITEM_PIPELINES = {
#    "NANKAIIR.pipelines.NankaiirPipeline": 300,
#}

# Enable and configure the AutoThrottle extension (disabled by default)
# See https://docs.scrapy.org/en/latest/topics/autothrottle.html
#AUTOTHROTTLE_ENABLED = True
# The initial download delay
#AUTOTHROTTLE_START_DELAY = 5
# The maximum download delay to be set in case of high latencies
# The average number of requests Scrapy should be sending in parallel to
# each remote server
#AUTOTHROTTLE_TARGET_CONCURRENCY = 1.0
# Enable showing throttling stats for every response received:
#AUTOTHROTTLE_DEBUG = False

# Enable and configure HTTP caching (disabled by default)
# See https://docs.scrapy.org/en/latest/topics/downloader-middleware.html#httpcache-middleware-settings
#HTTPCACHE_ENABLED = True
#HTTPCACHE_EXPIRATION_SECS = 0
#HTTPCACHE_DIR = "httpcache"
#HTTPCACHE_IGNORE_HTTP_CODES = []
#HTTPCACHE_STORAGE = "scrapy.extensions.httpcache.FilesystemCacheStorage"

# Set settings whose default value is deprecated to a future-proof value
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
FEED_EXPORT_ENCODING = "utf-8"
LOG_LEVEL = 'INFO'