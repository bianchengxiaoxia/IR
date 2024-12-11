from elasticsearch import Elasticsearch

# 初始化 Elasticsearch 客户端
es = Elasticsearch(
    hosts=["https://localhost:9200"],
    basic_auth=("elastic", "aWVrracnZiMZZDMLJ-fq"),
    verify_certs=False  # 本地测试时可设置为 False
)

count_response = es.count(index="web_pages")
print("Document count in 'web_pages':", count_response['count'])

# 查询索引内容
try:
    response = es.search(
        index="web_pages",
        body={
            "size": 100,
            "query": {"match_all": {}},
            "_source": ["title", "url", "pagerank"]  # 将pagerank字段也一起检索
        }
    )

    # 打印文档内容
    print(f"Total hits: {response['hits']['total']['value']}")
    for hit in response["hits"]["hits"]:
        source = hit["_source"]
        print("Title:", source.get("title", "N/A"))
        print("URL:", source.get("url", "N/A"))
        print("PageRank:", source.get("pagerank", "N/A"))
        print("publish_time", source.get("publish_time", "N/A"))
        print("-" * 50)

except Exception as e:
    print(f"Error querying Elasticsearch: {e}")

