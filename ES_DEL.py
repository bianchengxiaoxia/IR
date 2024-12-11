from elasticsearch import Elasticsearch

# 初始化 Elasticsearch 客户端
es = Elasticsearch(
    hosts=["https://localhost:9200"],
    basic_auth=("elastic", "aWVrracnZiMZZDMLJ-fq"),
    verify_certs=False
)

# 删除索引
index_name = "web_pages"
if es.indices.exists(index=index_name):
    es.indices.delete(index=index_name)
    print(f"Index '{index_name}' deleted successfully!")
else:
    print(f"Index '{index_name}' does not exist.")
