from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from elasticsearch import Elasticsearch

app = Flask(__name__)
CORS(app)  # 允许所有源访问，生产环境应做精确配置

# 初始化 Elasticsearch 客户端
es = Elasticsearch(
    hosts=["https://localhost:9200"],
    basic_auth=("elastic", "aWVrracnZiMZZDMLJ-fq"),
    verify_certs=False  # 根据需求配置证书验证
)

# 允许的排序字段和文档类型
ALLOWED_SORT_FIELDS = ["pagerank", "views", "publish_time"]
ALLOWED_FILE_TYPES = ["doc", "docx", "pdf", "xls", "xlsx"]

@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("query", "")
    page_str = request.args.get("page", "1")
    sort_field = request.args.get("sort_field", None)
    sort_order = request.args.get("sort_order", "desc")
    file_type = request.args.get("file_type", "")

    if not query:
        return jsonify({"error": "No query provided"}), 400

    # 处理页码参数
    try:
        page = int(page_str)
        if page < 1:
            page = 1
    except ValueError:
        page = 1

    page_size = 10
    from_value = (page - 1) * page_size

    # 构建查询体
    body = {
        "from": from_value,
        "size": page_size,
        "query": {
            "bool": {
                "must": [
                    {"multi_match": {
                        "query": query,
                        "fields": ["title", "content", "url", "publisher", "source"]
                    }},
                ],
                "filter": []
            }
        },
        "_source": ["title", "url", "pagerank", "content", "publish_time", "publisher", "source", "views", "images", "links", "attachments"]
    }

    # 文件类型过滤
    if file_type:
        if file_type.lower() not in ALLOWED_FILE_TYPES:
            return jsonify({"error": f"Unsupported file type: {file_type}"}), 400

        body["query"]["bool"]["filter"].append({
            "nested": {
                "path": "attachments",
                "query": {
                    "term": {"attachments.type": file_type.lower()}
                }
            }
        })

    # 排序字段验证
    sort_clause = [{"_score": {"order": "desc"}}]  # 默认相关性排序
    if sort_field:
        if sort_field not in ALLOWED_SORT_FIELDS:
            return jsonify({"error": f"Invalid sort field: {sort_field}"}), 400

        sort_clause.append({sort_field: {"order": sort_order}})

    if sort_clause:
        body["sort"] = sort_clause

    try:
        res = es.search(index="web_pages", body=body)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    total = res["hits"].get("total", {}).get("value", 0)
    hits_data = []
    for hit in res["hits"]["hits"]:
        source = hit["_source"]

        content = source.get("content", "")
        publish_time = source.get("publish_time", None)
        publisher = source.get("publisher", None)

        # 将 "未知" 替换为 None
        if publish_time == "未知":
            publish_time = None
        if publisher == "未知":
            publisher = None

        snippet = (content[:100] + "...") if len(content) > 100 else content

        # 返回更多字段，例如浏览量、附件信息等
        hits_data.append({
            "title": source.get("title", "无标题"),
            "url": source.get("url", ""),
            "pagerank": source.get("pagerank", "N/A"),
            "score": hit.get("_score", 0),
            "publish_time": publish_time,
            "publisher": publisher,
            "snippet": snippet,
            "views": source.get("views", None),
            "content": content,  # 返回完整内容
            "attachments": source.get("attachments", []),  # 返回附件信息
            "images": source.get("images", []),  # 假设有图片字段
        })

    # 计算总页数
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0

    return jsonify({
        "total": total,
        "hits": hits_data,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "sort_field": sort_field,
        "sort_order": sort_order
    })

@app.route("/detail", methods=["GET"])
def detail():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        res = es.get(index="web_pages", id=url)
        source = res["_source"]
        return jsonify(source)
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve details for URL: {url}", "details": str(e)}), 500

# 文档类型查询
@app.route("/api/query_documents", methods=["GET"])
def query_documents():
    doc_type = request.args.get('doc_type')
    if not doc_type:
        return jsonify({"error": "缺少文档类型参数"}), 400

    if doc_type.lower() not in ALLOWED_FILE_TYPES:
        return jsonify({"error": f"Unsupported document type: {doc_type}"}), 400

    query = {
        "query": {
            "nested": {
                "path": "attachments",
                "query": {
                    "term": {"attachments.type": doc_type.lower()}
                }
            }
        },
        "_source": ["attachments.name", "attachments.url", "attachments.type", "title", "url"]
    }

    try:
        res = es.search(index="web_pages", body=query, size=100)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    results = []
    for hit in res['hits']['hits']:
        for attachment in hit['_source'].get('attachments', []):
            if attachment.get('type', '').lower() == doc_type.lower():
                results.append({
                    "name": attachment.get("name", "无名称"),
                    "url": attachment.get("url", ""),
                    "type": attachment.get("type", ""),
                    "page_title": hit['_source'].get("title", "无标题"),
                    "page_url": hit['_source'].get("url", "")
                })

    return jsonify(results)

# 提供静态文件服务
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/detail.html')
def serve_detail():
    return send_from_directory('.', 'detail.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
