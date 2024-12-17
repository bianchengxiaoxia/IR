from dotenv import load_dotenv
import os

load_dotenv()  # 这一行确保 .env 文件被加载

# 示例：打印某个环境变量
print("DATABASE_URL:", os.getenv("DATABASE_URL"))
