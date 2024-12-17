from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from elasticsearch import Elasticsearch
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

from flask_session import Session
import redis
from dotenv import load_dotenv
import uuid  # 新增导入
import json  # 新增导入

# 加载 .env 文件中的环境变量
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')

# 配置秘钥（用于会话管理），从环境变量中读取
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise ValueError("未设置 SECRET_KEY 环境变量")
app.config['SECRET_KEY'] = secret_key

# 使用 MySQL 数据库存储用户和查询历史
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise ValueError("未设置 DATABASE_URL 环境变量")
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 配置服务器端会话存储（可选）
redis_url = os.getenv('REDIS_URL')
if redis_url:
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REDIS'] = redis.from_url(redis_url)
else:
    # 使用默认的客户端会话
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True

# 配置会话 cookie 属性
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 防止CSRF，同时允许同一站点下的跨页面请求发送 Cookie
app.config['SESSION_COOKIE_SECURE'] = False   # 开发环境下设置为 False，生产环境下建议设置为 True

# 初始化 Flask-Session
Session(app)

# 配置 CORS
CORS(app, supports_credentials=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 定义用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # 从 128 增加到 255

    search_histories = db.relationship('SearchHistory', backref='user', lazy=True)
    chat_histories = db.relationship('ChatHistory', backref='user', lazy=True)
    snapshots = db.relationship('Snapshot', backref='user', lazy=True)  # 新增关系

# 定义查询历史模型
class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    search_query = db.Column(db.String(255), nullable=False)
    search_mode = db.Column(db.String(50), nullable=False)  # 'normal' 或 'document'
    file_type = db.Column(db.String(10), nullable=True)
    sort_field = db.Column(db.String(50), nullable=True)
    sort_order = db.Column(db.String(10), nullable=True)
    page = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    search_count = db.Column(db.Integer, default=1, nullable=False)  # 新增字段

# 定义聊天历史模型
class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# 定义快照模型（新增）
class Snapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    search_query = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text, nullable=False)  # JSON serialized list of links

# 初始化 Elasticsearch 客户端
elasticsearch_host = os.getenv('ELASTICSEARCH_HOST')
elasticsearch_user = os.getenv('ELASTICSEARCH_USER')
elasticsearch_password = os.getenv('ELASTICSEARCH_PASSWORD')
elasticsearch_verify_certs = os.getenv('ELASTICSEARCH_VERIFY_CERTS', '0')

if not all([elasticsearch_host, elasticsearch_user, elasticsearch_password]):
    raise ValueError("未设置 Elasticsearch 的必要环境变量")

es = Elasticsearch(
    [elasticsearch_host],
    basic_auth=(elasticsearch_user, elasticsearch_password),
    verify_certs=bool(int(elasticsearch_verify_certs))
)

# 允许的排序字段和文档类型
ALLOWED_SORT_FIELDS = ["pagerank", "views", "publish_time"]
ALLOWED_FILE_TYPES = ["doc", "docx", "pdf", "xls", "xlsx"]

# 配置日志记录
logger = logging.getLogger('search_logger')
logger.setLevel(logging.DEBUG)  # 设置为 DEBUG 以捕获更多日志信息

# 文件处理器
file_handler = RotatingFileHandler('search_logs.log', maxBytes=1000000, backupCount=5, encoding='utf-8')
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# 控制台处理器
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


def log_query_to_database(user_id, query, search_mode, file_type, sort_field, sort_order):
    try:
        # 检查是否存在相同的搜索记录（移除 'page' 字段）
        existing_entry = SearchHistory.query.filter_by(
            user_id=user_id,
            search_query=query,
            search_mode=search_mode,
            file_type=file_type if file_type else None,
            sort_field=sort_field if sort_field else None,
            sort_order=sort_order
        ).first()

        if existing_entry:
            existing_entry.search_count += 1  # 增加搜索次数
            existing_entry.timestamp = datetime.utcnow()  # 更新时间
            db.session.commit()
            logger.info(f"Incremented search_count for user {user_id}: {query}")
        else:
            search_history = SearchHistory(
                user_id=user_id,
                search_query=query,
                search_mode=search_mode,
                file_type=file_type if file_type else None,
                sort_field=sort_field if sort_field else None,
                sort_order=sort_order,
                search_count=1  # 初始化搜索次数
            )
            db.session.add(search_history)
            db.session.commit()
            logger.info(f"Logged search query for user {user_id}: {query}")
    except Exception as e:
        logger.error(f"Failed to log query to database: {e}", exc_info=True)


def log_chat_to_database(user_id, message):
    try:
        chat_history = ChatHistory(
            user_id=user_id,
            message=message
        )
        db.session.add(chat_history)
        db.session.commit()
        logger.info(f"Logged chat message for user {user_id}: {message}")
    except Exception as e:
        logger.error(f"Failed to log chat to database: {e}", exc_info=True)

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

from uuid import uuid4

@app.before_request
def before_request():
    request_id = str(uuid4())
    request.environ['request_id'] = request_id
    logger.info(f"Request {request_id} started. URL: {request.url}, User-Agent: {request.headers.get('User-Agent')}")

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_id = request.environ.get('request_id', 'unknown')
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"[{request_id}] Unhandled exception: {e}", exc_info=True)
            return jsonify({"error": "Internal server error", "details": str(e), "request_id": request_id}), 500
    return decorated_function

# 路由 - 主页
@app.route('/')
def serve_index():
    return render_template('index.html')

# 路由 - 详情页
@app.route('/detail.html')
def serve_detail():
    return render_template('detail.html')

# 路由 - 登录页
@app.route('/login.html')
def serve_login():
    return render_template('login.html')

# 路由 - 注册页
@app.route('/register.html')
def serve_register():
    return render_template('register.html')

# 用户注册
@app.route("/api/register", methods=["POST"])
@handle_errors
def register():
    logger.info("Received registration request.")
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        logger.warning("Registration failed: Missing username or password.")
        return jsonify({"error": "用户名和密码是必需的"}), 400

    username = data['username'].strip()
    password = data['password'].strip()

    if not username or not password:
        logger.warning("Registration failed: Empty username or password.")
        return jsonify({"error": "用户名和密码不能为空"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        logger.warning(f"Registration failed: Username '{username}' already exists.")
        return jsonify({"error": "用户名已存在"}), 400

    try:
        password_hash = generate_password_hash(password)
        logger.info(f"Password hashed for user '{username}'.")
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        logger.info(f"Added new user '{username}' to the session.")
        db.session.commit()
        logger.info(f"Committed new user '{username}' to the database.")

        # 设置会话
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        logger.info(f"User '{username}' session set.")
        logger.info(f"User {new_user.id} ({new_user.username}) registered from IP {get_client_ip()}")
        return jsonify({"message": "注册成功"}), 201
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        return jsonify({"error": "注册失败", "details": str(e)}), 500

# 用户登录
@app.route("/api/login", methods=["POST"])
@handle_errors
def login():
    # 生成一个唯一的请求ID，用于追踪日志
    request_id = str(uuid.uuid4())
    user_agent = request.headers.get('User-Agent', 'Unknown')
    referer = request.headers.get('Referer', 'Unknown')
    logger.info(f"[{request_id}] Received login request from User-Agent: {user_agent}, Referer: {referer}")

    data = request.get_json()
    logger.debug(f"[{request_id}] Request data: {data}")

    if not data or 'username' not in data or 'password' not in data:
        logger.warning(f"[{request_id}] Login failed: Missing username or password.")
        return jsonify({"error": "用户名和密码是必需的"}), 400

    username = data['username'].strip()
    password = data['password'].strip()

    if not username or not password:
        logger.warning(f"[{request_id}] Login failed: Empty username or password.")
        return jsonify({"error": "用户名和密码不能为空"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        logger.warning(f"[{request_id}] Login failed: User '{username}' does not exist.")
        return jsonify({"error": "用户不存在"}), 404

    if not check_password_hash(user.password_hash, password):
        logger.warning(f"[{request_id}] Login failed: Incorrect password for user '{username}'.")
        return jsonify({"error": "密码不正确"}), 401

    # 检查当前会话是否已设置
    if 'user_id' in session:
        if session['user_id'] == user.id:
            logger.info(f"[{request_id}] Session already exists for user {session['user_id']} ({session.get('username')}).")
            return jsonify({"message": "登录成功"}), 200
        else:
            # 处理会话冲突（不同用户）
            logger.warning(f"[{request_id}] Session conflict: Different user is already logged in.")
            return jsonify({"error": "另一个用户已登录，请先登出。"}), 400
    else:
        # 设置会话
        session['user_id'] = user.id
        session['username'] = user.username
        logger.info(f"[{request_id}] User {user.id} ({user.username}) session set.")

    logger.info(f"[{request_id}] User {user.id} ({user.username}) logged in from IP {get_client_ip()}")

    return jsonify({"message": "登录成功"}), 200

# 用户登出
@app.route("/api/logout", methods=["POST"])
@handle_errors
@login_required
def logout():
    user_id = session.pop('user_id', None)
    username = session.pop('username', None)
    logger.info(f"User {user_id} ({username}) logged out from IP {get_client_ip()}")
    return jsonify({"message": "登出成功"}), 200

# 获取当前登录用户的信息
@app.route("/api/current_user", methods=["GET"])
@handle_errors
@login_required
def current_user():
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        return jsonify({"username": user.username, "user_id": user.id}), 200
    else:
        logger.warning(f"Current user lookup failed: User ID {user_id} does not exist.")
        return jsonify({"error": "用户不存在"}), 404

def get_user_interests(user_id):
    # 获取用户最近20条搜索记录
    histories = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.timestamp.desc()).limit(20).all()
    # 提取关键词，假设搜索查询已经是关键词
    keywords = [history.search_query for history in histories if history.search_query]
    return keywords


# 搜索功能
# 搜索功能
@app.route("/search", methods=["GET"])
@handle_errors
@login_required
def search():
    user_id = session['user_id']
    query = request.args.get("query", "").strip()
    page_str = request.args.get("page", "1")
    sort_field = request.args.get("sort_field", None)
    sort_order = request.args.get("sort_order", "desc")
    file_type = request.args.get("file_type", "").strip()
    phrase = request.args.get("phrase", "false").lower() == "true"
    wildcard = request.args.get("wildcard", "false").lower() == "true"

    if not query:
        logger.warning(f"Search failed for user {user_id}: No query provided.")
        return jsonify({"error": "未提供查询内容"}), 400

    MAX_PAGE = 10  # 最大页数为10

    # 处理页码参数
    try:
        page = int(page_str)
        if page < 1:
            page = 1
        elif page > MAX_PAGE:
            page = MAX_PAGE
    except ValueError:
        page = 1

    page_size = 10
    from_value = (page - 1) * page_size
    if from_value >= MAX_PAGE * page_size:
        from_value = (MAX_PAGE - 1) * page_size
        page = MAX_PAGE

    # 初始化查询子句
    must_clauses = []
    filter_clauses = []
    should_clauses = []
    search_mode = 'document' if file_type else 'normal'

    # 处理文件类型过滤
    if file_type:
        if file_type.lower() not in ALLOWED_FILE_TYPES:
            logger.warning(f"Search failed for user {user_id}: Unsupported file type '{file_type}'.")
            return jsonify({"error": f"不支持的文件类型: {file_type}"}), 400

        filter_clauses.append({
            "nested": {
                "path": "attachments",
                "query": {
                    "term": {"attachments.type": file_type.lower()}
                }
            }
        })

    # 获取用户兴趣关键词
    user_interests = get_user_interests(user_id)
    if user_interests:
        for interest in user_interests:
            should_clauses.append({
                "match": {
                    "content": {
                        "query": interest,
                        "boost": 2  # 根据需求调整boost值
                    }
                }
            })mi

    # 构建普通查询子句
    if phrase:
        must_clauses.append({
            "multi_match": {
                "query": query,
                "type": "phrase",
                "fields": ["title^2", "content"],
                "slop": 2  # 根据需求调整 slop 值
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

    # 定义通配符查询体
    def build_wildcard_query(query):
        wildcard_queries = []
        for field in ALLOWED_QUERY_FIELDS:
            wildcard_queries.append({
                "wildcard": {
                    field: {
                        "value": query,
                        "boost": 1.0,
                        "rewrite": "constant_score"  # 提高查询效率
                    }
                }
            })
        return {
            "bool": {
                "should": wildcard_queries,
                "minimum_should_match": 1
            }
        }

    # 定义普通查询体
    def build_normal_query():
        return {
            "bool": {
                "must": must_clauses,
                "filter": filter_clauses,
                "should": should_clauses,
                "minimum_should_match": 1 if should_clauses else 0
            }
        }

    # 定义 Function Score 查询体
    def build_function_score_query(query_body):
        return {
            "from": from_value,
            "size": page_size,
            "query": {
                "function_score": {
                    "query": query_body,
                    "script_score": {
                        "script": {
                            "source": "_score + doc['pagerank'].value"
                        }
                    },
                    "boost_mode": "replace"  # 使用脚本评分替换原始评分
                }
            },
            "_source": ["title", "url", "pagerank", "content", "publish_time", "publisher", "source", "views", "images",
                        "links", "attachments"]
        }

    # 将查询记录存储到数据库
    log_query_to_database(
        user_id=user_id,
        query=query,
        search_mode=search_mode,
        file_type=file_type if file_type else None,
        sort_field=sort_field if sort_field else None,
        sort_order=sort_order
    )

    # 记录到日志文件
    user_ip = get_client_ip()
    logger.info(f"User {user_id} searched: {query}, mode={search_mode}, file_type={file_type}, page={page}, IP={user_ip}")

    try:
        if wildcard and ("*" in query or "?" in query):
            # 禁止前导通配符
            if query.startswith("*") or query.startswith("?"):
                logger.warning(f"Search failed for user {user_id}: Leading wildcard used in query '{query}'.")
                return jsonify({"error": "前导通配符会导致性能问题，请避免使用"}), 400

            # 构建通配符查询
            wildcard_query_body = build_function_score_query(build_wildcard_query(query))

            logger.debug(f"Executing wildcard query for user {user_id}: {json.dumps(wildcard_query_body, ensure_ascii=False)}")

            res = es.search(index="web_pages", body=wildcard_query_body)

            total = res["hits"].get("total", {}).get("value", 0)

            if total == 0:
                # 如果通配符查询没有结果，则回退到普通查询
                logger.info(f"Wildcard query returned no results for user {user_id}. Falling back to normal query.")
                normal_query_body = build_function_score_query(build_normal_query())
                res = es.search(index="web_pages", body=normal_query_body)
                total = res["hits"].get("total", {}).get("value", 0)
            else:
                logger.info(f"Wildcard query returned {total} results for user {user_id}.")

        else:
            # 构建普通查询
            normal_query_body = build_function_score_query(build_normal_query())

            logger.debug(f"Executing normal query for user {user_id}: {json.dumps(normal_query_body, ensure_ascii=False)}")

            res = es.search(index="web_pages", body=normal_query_body)

            total = res["hits"].get("total", {}).get("value", 0)

        hits_data = []
        links = []  # 收集链接信息 for snapshot
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
            # Collect links
            links.append({
                "title": source.get("title", "无标题"),
                "url": source.get("url", "")
            })

        total_pages = min((total + page_size - 1) // page_size, MAX_PAGE) if total > 0 else 0

        # 将搜索结果保存为快照（仅保存链接和标题）
        save_snapshot(
            user_id=user_id,
            query=query,
            results=links
        )

        return jsonify({
            "total": total,
            "hits": hits_data,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "sort_field": sort_field,
            "sort_order": sort_order
        })

    except Exception as e:
        logger.error(f"Elasticsearch search error for user {user_id}: {e}", exc_info=True)
        return jsonify({"error": "搜索服务不可用", "details": str(e)}), 500


# 定义快照保存函数（新增）
def save_snapshot(user_id, query, results):
    try:
        snapshot = Snapshot(
            user_id=user_id,
            search_query=query,
            results=json.dumps(results, ensure_ascii=False)  # 将结果转换为JSON字符串
        )
        db.session.add(snapshot)
        db.session.commit()
        logger.info(f"用户 {user_id} 保存了搜索快照: '{query}'。")
    except Exception as e:
        logger.error(f"保存搜索快照失败: {e}", exc_info=True)

# 列出所有快照（新增）
@app.route("/api/snapshots", methods=["GET"])
@handle_errors
@login_required
def list_snapshots():
    user_id = session['user_id']
    snapshots = Snapshot.query.filter_by(user_id=user_id).order_by(Snapshot.timestamp.desc()).all()
    snapshot_list = []
    for snap in snapshots:
        snapshot_list.append({
            "id": snap.id,
            "search_query": snap.search_query,
            "timestamp": snap.timestamp.isoformat()
        })
    logger.info(f"用户 {user_id} 获取了快照列表。")
    return jsonify(snapshot_list)

# 查看特定快照（新增）
@app.route("/api/snapshots/<int:snapshot_id>", methods=["GET"])
@handle_errors
@login_required
def view_snapshot(snapshot_id):
    user_id = session['user_id']
    snapshot = Snapshot.query.filter_by(id=snapshot_id, user_id=user_id).first()
    if not snapshot:
        logger.warning(f"快照 {snapshot_id} 未找到，用户 {user_id}。")
        return jsonify({"error": "快照未找到"}), 404
    return jsonify({
        "id": snapshot.id,
        "search_query": snapshot.search_query,
        "timestamp": snapshot.timestamp.isoformat(),
        "results": json.loads(snapshot.results)
    })

# 删除快照（新增）
@app.route("/api/snapshots/<int:snapshot_id>", methods=["DELETE"])
@handle_errors
@login_required
def delete_snapshot(snapshot_id):
    user_id = session['user_id']
    snapshot = Snapshot.query.filter_by(user_id=user_id, id=snapshot_id).first()
    if snapshot:
        try:
            db.session.delete(snapshot)
            db.session.commit()
            logger.info(f"用户 {user_id} 删除了快照 {snapshot_id}。")
            return jsonify({"message": "快照已删除"}), 200
        except Exception as e:
            logger.error(f"删除快照 {snapshot_id} 失败，用户 {user_id}: {e}", exc_info=True)
            return jsonify({"error": "删除快照失败"}), 500
    else:
        logger.warning(f"删除快照失败：快照 {snapshot_id} 未找到，用户 {user_id}。")
        return jsonify({"error": "未找到对应的快照"}), 404

# 删除所有快照（新增，可选）
@app.route("/api/snapshots", methods=["DELETE"])
@handle_errors
@login_required
def delete_all_snapshots():
    user_id = session['user_id']
    try:
        deleted = Snapshot.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        logger.info(f"用户 {user_id} 删除了所有快照。")
        return jsonify({"message": "所有快照已删除"}), 200
    except Exception as e:
        logger.error(f"删除所有快照失败，用户 {user_id}: {e}", exc_info=True)
        return jsonify({"error": "删除快照失败"}), 500


# 列出用户的搜索历史记录
@app.route("/api/query_history", methods=["GET"])
@handle_errors
@login_required
def query_history():
    user_id = session['user_id']
    # 获取用户的所有搜索历史，按时间降序排列
    histories = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.timestamp.desc()).all()

    # 将搜索历史转换为 JSON 可序列化的格式
    history_list = []
    for entry in histories:
        history_list.append({
            "id": entry.id,
            "query": entry.search_query,  # 确保字段名为 'query'
            "search_mode": entry.search_mode,
            "file_type": entry.file_type,
            "sort_field": entry.sort_field,
            "sort_order": entry.sort_order,
            "page": entry.page,
            "search_count": entry.search_count,
            "timestamp": entry.timestamp.isoformat()
        })

    logger.info(f"用户 {user_id} 获取了搜索历史记录。")

    return jsonify(history_list), 200

# 删除当前用户的查询历史（支持删除单条记录）
@app.route("/api/delete_history", methods=["POST"])
@handle_errors
@login_required
def delete_history():
    user_id = session['user_id']
    data = request.get_json()
    if not data or 'id' not in data:
        # 如果没有提供id，则删除所有历史记录
        try:
            deleted = SearchHistory.query.filter_by(user_id=user_id).delete()
            db.session.commit()
            logger.info(f"User {user_id} cleared all search history.")
            return jsonify({"message": "查询历史已清空"}), 200
        except Exception as e:
            logger.error(f"Error clearing search history for user {user_id}: {e}", exc_info=True)
            return jsonify({"error": "删除查询历史失败"}), 500
    else:
        # 删除指定id的历史记录
        history_id = data['id']
        history_entry = SearchHistory.query.filter_by(user_id=user_id, id=history_id).first()
        if history_entry:
            try:
                db.session.delete(history_entry)
                db.session.commit()
                logger.info(f"User {user_id} deleted search history entry {history_id}.")
                return jsonify({"message": "查询历史已删除"}), 200
            except Exception as e:
                logger.error(f"Error deleting search history entry {history_id} for user {user_id}: {e}", exc_info=True)
                return jsonify({"error": "删除查询历史失败"}), 500
        else:
            logger.warning(f"Delete history failed: History entry {history_id} not found for user {user_id}.")
            return jsonify({"error": "未找到对应的历史记录"}), 404

# 查询文档
@app.route("/api/query_documents", methods=["GET"])
@handle_errors
@login_required
def query_documents():
    query_str = request.args.get('query', '').strip()
    doc_type = request.args.get('doc_type', '').lower().strip()

    if not query_str:
        logger.warning(f"Query documents failed for user {session.get('user_id')}: Missing query string.")
        return jsonify({"error": "缺少查询内容参数"}), 400

    if not doc_type:
        logger.warning(f"Query documents failed for user {session.get('user_id')}: Missing document type.")
        return jsonify({"error": "缺少文档类型参数"}), 400

    if doc_type not in ALLOWED_FILE_TYPES:
        logger.warning(f"Query documents failed for user {session.get('user_id')}: Unsupported document type '{doc_type}'.")
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
        logger.error(f"Elasticsearch query_documents error for user {session.get('user_id')}: {e}", exc_info=True)
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

    logger.info(f"User {session.get('user_id')} queried documents with type '{doc_type}'.")

    return jsonify(results)
@app.route("/api/detail", methods=["GET"])
@handle_errors
@login_required
def detail():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        # 使用 Elasticsearch 搜索文档，匹配 url 字段
        res = es.search(
            index="web_pages",
            body={
                "query": {
                    "term": {
                        "url": url
                    }
                },
                "size": 1  # 只获取一个结果
            }
        )
        hits = res["hits"]["hits"]
        if not hits:
            logger.warning(f"No document found for URL: {url}")
            return jsonify({"error": "文档未找到"}), 404
        source = hits[0]["_source"]
        return jsonify(source)
    except Exception as e:
        logger.error(f"Elasticsearch detail error: {e}", exc_info=True)
        return jsonify({"error": f"Failed to retrieve details for URL: {url}", "details": str(e)}), 500


# 在后端代码的适当位置添加以下内容
# 定义允许查询的字段
ALLOWED_QUERY_FIELDS = ["title", "content", "url", "publisher", "source"]
@app.route("/api/search_suggestions", methods=["GET"])
@handle_errors
@login_required
def search_suggestions():
    user_id = session['user_id']
    partial_query = request.args.get("q", "").strip()

    if not partial_query:
        return jsonify({"suggestions": []}), 200  # 如果查询为空，返回空列表

    suggestions = []
    seen_titles_urls = set()

    # 1. 基于用户的搜索历史获取相关的搜索词
    historical_queries = SearchHistory.query.filter(
        SearchHistory.user_id == user_id,
        SearchHistory.search_query.ilike(f"%{partial_query}%")
    ).order_by(SearchHistory.search_count.desc()).limit(10).all()

    for entry in historical_queries:
        search_query = entry.search_query
        # 构建Elasticsearch查询体
        suggest_query = {
            "size": 1,  # 只需要一个匹配
            "query": {
                "multi_match": {
                    "query": search_query,
                    "fields": ["title", "content"]
                }
            },
            "sort": [{"_score": {"order": "desc"}}]
        }

        try:
            res = es.search(index="web_pages", body=suggest_query)
            for hit in res['hits']['hits']:
                title = hit['_source'].get('title', '').strip()
                url = hit['_source'].get('url', '').strip()
                if title and url:
                    # 使用元组确保唯一性
                    if (title, url) not in seen_titles_urls:
                        suggestions.append({"title": title, "url": url})
                        seen_titles_urls.add((title, url))
                        break  # 只需要第一个匹配
        except Exception as e:
            logger.error(f"Elasticsearch search_suggestions error for user {user_id} with search_query '{search_query}': {e}", exc_info=True)
            continue  # 继续处理下一个搜索查询

        if len(suggestions) >= 5:
            break  # 达到5个建议后停止

    # 2. 基于当前输入直接从ES获取联想词
    if len(suggestions) < 5:
        remaining = 5 - len(suggestions)
        direct_suggest_query = {
            "size": remaining,
            "query": {
                "multi_match": {
                    "query": partial_query,
                    "fields": ["title^3", "content"],  # 增加title的权重
                    "type": "phrase_prefix"  # 使用phrase_prefix以支持前缀匹配
                }
            },
            "sort": [{"_score": {"order": "desc"}}]
        }

        try:
            res = es.search(index="web_pages", body=direct_suggest_query)
            for hit in res['hits']['hits']:
                title = hit['_source'].get('title', '').strip()
                url = hit['_source'].get('url', '').strip()
                if title and url:
                    if (title, url) not in seen_titles_urls:
                        suggestions.append({"title": title, "url": url})
                        seen_titles_urls.add((title, url))
                        if len(suggestions) >= 5:
                            break
        except Exception as e:
            logger.error(f"Elasticsearch direct_suggestions error for user {user_id} with partial_query '{partial_query}': {e}", exc_info=True)

    return jsonify(suggestions), 200




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
