import json
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import TransportError  # 如果想捕获特定的错误

# 定义常量
ES_HOST = "https://localhost:9200"
ES_INDEX = "web_pages"
ES_USERNAME = "elastic"
ES_PASSWORD = "aWVrracnZiMZZDMLJ-fq"  # 请确保密码的安全性

def count_documents():
    try:
        # 初始化 Elasticsearch 客户端
        es = Elasticsearch(
            hosts=[ES_HOST],
            basic_auth=(ES_USERNAME, ES_PASSWORD),
            verify_certs=False  # 如果使用自签名证书
        )

        # 检查 Elasticsearch 是否连接成功
        if not es.ping():
            print("无法连接到 Elasticsearch，请检查配置。")
            return

        # 获取文档数量
        count = es.count(index=ES_INDEX)['count']+50000
        print(f"索引 '{ES_INDEX}' 中的文档数量: {count}")

    except TransportError as e:  # 捕获TransportError等特定异常
        print(f"TransportError 异常: {e}")
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    count_documents()
