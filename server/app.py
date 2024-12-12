from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from elasticsearch import Elasticsearch
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os
import uuid  # 修正导入错误
from functools import wraps  # 添加缺失的导入

app = Flask(__name__)
CORS(app)  # 允许所有源访问，生产环境应做精确配置

# 配置秘钥（用于会话管理），推荐使用环境变量
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')

# 使用 SQLite 数据库存储查询历史，建议切换到更高效的数据库如 PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///search_history.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 定义查询历史模型
class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), nullable=False)  # UUID字符串
    search_query = db.Column(db.String(255), nullable=False)  # 重命名为 search_query
    search_mode = db.Column(db.String(50), nullable=False)  # 'normal' 或 'document'
    file_type = db.Column(db.String(10), nullable=True)
    sort_field = db.Column(db.String(50), nullable=True)
    sort_order = db.Column(db.String(10), nullable=True)
    page = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# 初始化 Elasticsearch 客户端（请根据实际情况修改）
es = Elasticsearch(
    hosts=[os.getenv('ELASTICSEARCH_HOST', "https://localhost:9200")],
    basic_auth=(os.getenv('ELASTICSEARCH_USER', "elastic"), os.getenv('ELASTICSEARCH_PASSWORD', "aWVrracnZiMZZDMLJ-fq")),
    verify_certs=bool(int(os.getenv('ELASTICSEARCH_VERIFY_CERTS', "0")))  # 根据需求配置证书验证
)

# 允许的排序字段和文档类型
ALLOWED_SORT_FIELDS = ["pagerank", "views", "publish_time"]
ALLOWED_FILE_TYPES = ["doc", "docx", "pdf", "xls", "xlsx"]

# 配置日志记录（可选）
handler = RotatingFileHandler('search_logs.log', maxBytes=1000000, backupCount=5, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)

logger = logging.getLogger('search_logger')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def get_user_id():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    return session['user_id']

def log_query_to_database(user_id, query, search_mode, file_type, sort_field, sort_order, page):
    try:
        search_history = SearchHistory(
            user_id=user_id,
            search_query=query,  # 更新为 search_query
            search_mode=search_mode,
            file_type=file_type if file_type else None,
            sort_field=sort_field if sort_field else None,
            sort_order=sort_order,
            page=page
        )
        db.session.add(search_history)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log query to database: {e}", exc_info=True)

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Unhandled exception: {e}", exc_info=True)
            return jsonify({"error": "Internal server error", "details": str(e)}), 500
    return decorated_function

@app.route("/search", methods=["GET"])
@handle_errors
def search():
    user_id = get_user_id()
    query = request.args.get("query", "").strip()
    page_str = request.args.get("page", "1")
    sort_field = request.args.get("sort_field", None)
    sort_order = request.args.get("sort_order", "desc")
    file_type = request.args.get("file_type", "").strip()
    phrase = request.args.get("phrase", "false").lower() == "true"
    wildcard = request.args.get("wildcard", "false").lower() == "true"

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
    must_clauses = []
    if wildcard:
        # 支持通配符查询，避免前导通配符
        if query.startswith("*") or query.startswith("?"):
            # 如果用户使用了前导通配符，警告或限制
            return jsonify({"error": "前导通配符会导致性能问题，请避免使用"}), 400
        must_clauses.append({
            "wildcard": {
                "content": {
                    "value": query,
                    "boost": 1.0,
                    "rewrite": "constant_score"
                }
            }
        })
    elif phrase:
        # 使用 match_phrase 并添加 slop 参数以支持灵活匹配
        must_clauses.append({
            "match_phrase": {
                "content": {
                    "query": query,
                    "slop": 2  # 根据需求调整 slop 值
                }
            }
        })
    else:
        must_clauses.append({
            "multi_match": {
                "query": query,
                "fields": ["title", "content", "url", "publisher", "source"],
                "type": "best_fields",
                "operator": "and"
            }
        })

    filter_clauses = []
    search_mode = 'document' if file_type else 'normal'
    if file_type:
        if file_type.lower() not in ALLOWED_FILE_TYPES:
            return jsonify({"error": f"Unsupported file type: {file_type}"}), 400

        filter_clauses.append({
            "nested": {
                "path": "attachments",
                "query": {
                    "term": {"attachments.type": file_type.lower()}
                }
            }
        })

    body = {
        "from": from_value,
        "size": page_size,
        "query": {
            "bool": {
                "must": must_clauses,
                "filter": filter_clauses
            }
        },
        "_source": ["title", "url", "pagerank", "content", "publish_time", "publisher", "source", "views", "images",
                    "links", "attachments"]
    }

    # 排序字段验证
    sort_clause = [{"_score": {"order": "desc"}}]
    if sort_field:
        if sort_field not in ALLOWED_SORT_FIELDS:
            return jsonify({"error": f"Invalid sort field: {sort_field}"}), 400
        sort_clause.append({sort_field: {"order": sort_order}})

    if sort_clause:
        body["sort"] = sort_clause

    # 将查询记录存储到数据库
    log_query_to_database(
        user_id=user_id,
        query=query,
        search_mode=search_mode,
        file_type=file_type if file_type else None,
        sort_field=sort_field if sort_field else None,
        sort_order=sort_order,
        page=page
    )

    # 可选：记录到日志文件
    user_ip = get_client_ip()
    logger.info(f"User {user_id} searched: {query}, mode={search_mode}, file_type={file_type}, page={page}, IP={user_ip}")

    try:
        res = es.search(index="web_pages", body=body)
    except Exception as e:
        logger.error(f"Elasticsearch search error: {e}", exc_info=True)
        return jsonify({"error": "Search service is unavailable", "details": str(e)}), 500

    total = res["hits"].get("total", {}).get("value", 0)
    hits_data = []
    for hit in res["hits"]["hits"]:
        source = hit["_source"]

        content = source.get("content", "")
        publish_time = source.get("publish_time", None)
        publisher = source.get("publisher", None)

        if publish_time == "未知":
            publish_time = None
        if publisher == "未知":
            publisher = None

        snippet = (content[:100] + "...") if len(content) > 100 else content

        hits_data.append({
            "title": source.get("title", "无标题"),
            "url": source.get("url", ""),
            "pagerank": source.get("pagerank", "N/A"),
            "score": hit.get("_score", 0),
            "publish_time": publish_time,
            "publisher": publisher,
            "snippet": snippet,
            "views": source.get("views", None),
            "content": content,
            "attachments": source.get("attachments", []),
            "images": source.get("images", [])
        })

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

# 获取当前用户的查询历史
@app.route("/api/query_history", methods=["GET"])
@handle_errors
def query_history():
    user_id = get_user_id()
    history_entries = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.timestamp.desc()).all()
    history_list = []
    for entry in history_entries:
        history_list.append({
            "id": entry.id,  # 添加id字段
            "query": entry.search_query,  # 更新为 search_query
            "search_mode": entry.search_mode,
            "file_type": entry.file_type,
            "sort_field": entry.sort_field,
            "sort_order": entry.sort_order,
            "page": entry.page,
            "timestamp": entry.timestamp.isoformat()
        })
    return jsonify(history_list)

# 删除当前用户的查询历史（支持删除单条记录）
@app.route("/api/delete_history", methods=["POST"])
@handle_errors
def delete_history():
    user_id = get_user_id()
    data = request.get_json()
    if not data or 'id' not in data:
        # 如果没有提供id，则删除所有历史记录
        SearchHistory.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        return jsonify({"message": "查询历史已清空"}), 200
    else:
        # 删除指定id的历史记录
        history_id = data['id']
        history_entry = SearchHistory.query.filter_by(user_id=user_id, id=history_id).first()
        if history_entry:
            db.session.delete(history_entry)
            db.session.commit()
            return jsonify({"message": "查询历史已删除"}), 200
        else:
            return jsonify({"error": "未找到对应的历史记录"}), 404

@app.route("/detail", methods=["GET"])
@handle_errors
def detail():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        # 假设URL是文档的唯一标识符，并且作为 _id 存储在 Elasticsearch 中
        res = es.get(index="web_pages", id=url)
        source = res["_source"]
        return jsonify(source)
    except Exception as e:
        logger.error(f"Elasticsearch detail error: {e}", exc_info=True)
        return jsonify({"error": f"Failed to retrieve details for URL: {url}", "details": str(e)}), 500

@app.route("/api/query_documents", methods=["GET"])
@handle_errors
def query_documents():
    query_str = request.args.get('query', '').strip()
    doc_type = request.args.get('doc_type', '').lower().strip()

    if not query_str:
        return jsonify({"error": "缺少查询内容参数"}), 400

    if not doc_type:
        return jsonify({"error": "缺少文档类型参数"}), 400

    if doc_type not in ALLOWED_FILE_TYPES:
        return jsonify({"error": f"Unsupported document type: {doc_type}"}), 400

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": query_str,
                            "fields": ["title", "content", "attachments.name"],
                            "operator": "and"
                        }
                    }
                ],
                "filter": [
                    {
                        "nested": {
                            "path": "attachments",
                            "query": {
                                "term": {"attachments.type": doc_type}
                            }
                        }
                    }
                ]
            }
        },
        "_source": ["attachments.name", "attachments.url", "attachments.type", "title", "url"]
    }

    try:
        res = es.search(index="web_pages", body=query, size=100)
    except Exception as e:
        logger.error(f"Elasticsearch query_documents error: {e}", exc_info=True)
        return jsonify({"error": "Search service is unavailable", "details": str(e)}), 500

    results = []
    for hit in res['hits']['hits']:
        for attachment in hit['_source'].get('attachments', []):
            if attachment.get('type', '').lower() == doc_type:
                results.append({
                    "name": attachment.get("name", "无名称"),
                    "url": attachment.get("url", ""),
                    "type": attachment.get("type", ""),
                    "page_title": hit['_source'].get("title", "无标题"),
                    "page_url": hit['_source'].get("url", "")
                })

    return jsonify(results)

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/detail.html')
def serve_detail():
    return send_from_directory('.', 'detail.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
