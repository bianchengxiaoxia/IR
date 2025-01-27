#                            信息检索系统大作业实验报告

姓名：夏雨鍩

学号：2210204

专业：计算机科学与技术

## 1. 实验背景与要求

根据图片中给出的实验要求，本次实验需要完成以下五个步骤：

1. **网页抓取**：对南开校内资源进行爬取，并根据自己的主题进行数据收集。要求抓取的网页数量至少为 10 万条。必须严格遵守礼貌爬虫协议（robots 协议），并在校内网络环境下进行爬取。
2. **文本索引**：对网页及其文本内容进行索引，以便后续的查询与分析。可设置多重索引域，如网页标题、URL、正文文本、附件文本等。
3. **链接分析**：使用 PageRank 对抓取到的页面进行链接分析，评估网页权重。
4. **查询服务**：基于已建立的索引实现多种查询服务。
5. **个性化查询**：在查询服务基础上实现个性化查询功能，如根据用户偏好进行排序或推荐。

## 2. 实验环境与依赖

- 操作系统：Windows11
- Python版本：3.12（建议使用 Anaconda 虚拟环境）
- Scrapy：用于网页爬虫实现
- BeautifulSoup4：用于 HTML 解析
- Elasticsearch：用于全文索引与查询
- Elasticsearch Python 客户端 (`elasticsearch` 库)：与 Elasticsearch 通信
- redis :用于存储会话信息
- NetworkX：用于构建有向图并计算 PageRank
- 具体需要的库依赖可由requirement.txt获取

下面为报告的精简版，仅包括**1 网页抓取**、**2 文本索引**和**3 链接分析**这三个部分的内容，并结合代码片段进行说明。报告格式适合在 Typora 等 Markdown 编辑器中查看。

## 3. 网页抓取

本次实验采用 **Scrapy** 框架对南开校内资源进行网页抓取。爬虫主要逻辑如下：

- 使用 `start_urls` 定义起始点（如 `https://xb.nankai.edu.cn`）。
- 使用 `parse` 方法对响应结果进行解析。
- 对不符合要求的内容类型（如非文本类）进行过滤，对过短内容进行剔除。
- 使用 `BeautifulSoup` 对 HTML 进行解析，提取标题、正文、附件、图片等信息，并对发布者、来源、发布时间、浏览次数、联系方式等元信息进行正则匹配和清洗。
- 为避免重复爬取，通过 `visited_links.json` 存储已访问链接，从而实现断点续爬。
- 在代码中通过 `MIN_CONTENT_LENGTH` 对正文长度进行限制，正文过短则跳过保存与索引。

### 代码示例（网页抓取核心片段）

```python
def parse(self, response):
    if response.status != 200:
        # 状态码不为200则跳过
        self.visited_links.add(response.url)
        self.save_visited_links()
        return
    
    if response.url in self.visited_links:
        return

    # 检查是否为文本类响应
    content_type = response.headers.get('Content-Type', b'').decode().lower()
    if 'text' not in content_type:
        self.visited_links.add(response.url)
        self.save_visited_links()
        return
    
    self.visited_links.add(response.url)

    # 使用 BeautifulSoup 解析HTML
    soup = BeautifulSoup(response.text, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else "无标题"
    content = self.extract_main_content(soup, response.url)

    # 清洗与提取发布者、来源、发布时间、浏览次数、附件、图片等
    # （略，一般使用正则匹配patterns和HTML结构）

    # 正文长度检查
    if len(content.replace("\n", "").strip()) < self.MIN_CONTENT_LENGTH:
        self.save_visited_links()
        # 继续提取本页面中的其他链接进行爬取
        for link in self.extract_links(soup, response):
            yield Request(link, callback=self.parse, errback=self.errback_httpbin)
        return

    # 保存满足要求的页面为JSON文件
    page_data = {
        "unique_id": hashlib.md5(response.url.encode()).hexdigest(),
        "title": title,
        "url": response.url,
        "content": content,
        # 省略其他提取的字段...
    }

    file_name = os.path.join(self.save_dir, f"{title}_{page_data['unique_id']}.json")
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(page_data, f, ensure_ascii=False, indent=4)

    self.valid_page_count += 1
    self.index_to_elasticsearch(page_data)  # 后续文本索引

    self.save_visited_links()

    # 提取本页的有效链接，继续递归爬取
    for link in self.extract_links(soup, response):
        if link not in self.visited_links:
            yield Request(link, callback=self.parse, errback=self.errback_httpbin)
```

通过上述代码实现了对校内网站大规模网页的有序抓取与数据清洗，确保至少爬取10万页数据。

### 爬取文章数量查询

```python
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
        count = es.count(index=ES_INDEX)['count']
        print(f"索引 '{ES_INDEX}' 中的文档数量: {count}")

    except TransportError as e:  # 捕获TransportError等特定异常
        print(f"TransportError 异常: {e}")
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    count_documents()

```

这段代码通过 Python 的 Elasticsearch 客户端与 Elasticsearch 服务交互，统计指定索引中的文档数量。主要逻辑如下：

------

#### **核心流程**

1. **连接 Elasticsearch**:

   ```python
   es = Elasticsearch(
       hosts=[ES_HOST],
       basic_auth=(ES_USERNAME, ES_PASSWORD),
       verify_certs=False
   )
   ```

   - 使用指定的主机地址、用户名、密码初始化客户端。
   - 设置 `verify_certs=False` 忽略自签名证书验证。

2. **测试连接**:

   ```python
   if not es.ping():
       print("无法连接到 Elasticsearch，请检查配置。")
       return
   ```

   - 检查服务是否在线，避免后续操作失败。

3. **统计文档数量**:

   ```python
   count = es.count(index=ES_INDEX)['count']
   ```

   - 调用 `es.count()` 获取目标索引的文档总数，提取返回值中的 `count` 字段。

4. **异常处理**:

   ```python
   except TransportError as e:
       print(f"TransportError 异常: {e}")
   except Exception as e:
       print(f"发生错误: {e}")
   ```

   - 捕获与网络传输相关的错误或其他异常，确保代码稳健运行。

5. **输出结果**:

   ```python
   print(f"索引 '{ES_INDEX}' 中的文档数量: {count}")
   ```

------

#### **查询结果**

代码通过连接 Elasticsearch 服务，调用 `count` 方法获取指定索引的文档数量，同时包含基本的错误处理逻辑。结果显示数量大于10万。

![image-20241216220830789](./image-20241216220830789.png)

------

## 4. 文本索引

实验采用 **Elasticsearch** 作为全文检索引擎。文本索引过程在数据成功爬取与清洗后进行：

- 在爬虫初始化时，通过 `ensure_index()` 方法检测并创建 `web_pages` 索引。索引映射中定义了 `title`、`url`、`content`、`publish_time`、`images`、`links`、`publisher`、`views`、`attachments`、`contact_info`、`pagerank` 等字段。
- 在 `parse` 方法中，当页面数据准备就绪后，将其以 JSON 格式存储，并同时通过 `index_to_elasticsearch` 方法将数据提交到 Elasticsearch。
- 使用批量写入（`helpers.bulk`）方式提升索引效率，在达到一定数量（如 50 条）后一次性提交。

### 代码示例（文本索引相关片段）

```python
def ensure_index(self):
    if not self.es.indices.exists(index="web_pages"):
        mapping = {
            "mappings": {
                "properties": {
                    "unique_id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "url": {"type": "keyword"},
                    "publish_time": {"type": "date", "format": "yyyy-MM-dd"},
                    "content": {"type": "text"},
                    # 其他字段的映射...
                    "pagerank": {"type": "float"}
                }
            }
        }
        self.es.indices.create(index="web_pages", body=mapping)

def index_to_elasticsearch(self, data):
    action = {
        "_index": "web_pages",
        "_id": data["unique_id"],
        "_source": data
    }
    self.es_bulk.append(action)
    if len(self.es_bulk) >= self.bulk_size:
        success, errors = helpers.bulk(self.es, self.es_bulk, raise_on_error=False)
        self.indexed_ids.update([doc["_id"] for doc in self.es_bulk])
        self.es_bulk = []
```

通过该步骤，已抓取并清洗的页面文本及元数据被成功索引进入 Elasticsearch，以便后续查询与分析。

------

## 5. 链接分析

链接分析采用 **NetworkX** 计算 **PageRank**。主要步骤：

- 在爬取过程中，使用 `self.graph.add_edge(response.url, link)` 将页面之间的引用关系加入有向图中。
- 在爬虫结束时（`closed` 方法内），调用 `nx.pagerank(self.graph, alpha=0.85)` 计算每个URL的PageRank值。
- 将计算结果更新回 Elasticsearch，为后续查询排名与个性化推荐提供权重依据。

### 代码示例（链接分析片段）

```python
def parse(self, response):
    # ... 前面省略
    # 在解析后更新图数据
    self.graph.add_node(response.url)
    extracted_links = self.extract_links(soup, response)
    for link in extracted_links:
        if link not in self.visited_links:
            self.graph.add_edge(response.url, link)
    # ... 后面省略

def closed(self, reason):
    # 计算 PageRank
    pagerank = nx.pagerank(self.graph, alpha=0.85)
    for url, rank in pagerank.items():
        unique_id = self.url_to_id.get(url)
        if unique_id and unique_id in self.indexed_ids:
            self.es.update(
                index="web_pages",
                id=unique_id,
                body={"doc": {"pagerank": float(rank)}}
            )
```

通过此步骤，每个页面在全局链接图中的重要性得以量化，并存储于索引中，为后续查询排序策略（例如，根据PageRank以及ES自带的空间向量模型得出的分数对搜索结果重新排序）提供数据支持。

------

## 6 查询服务

本系统的查询服务基于 Elasticsearch 全文检索引擎和向量空间模型。通过利用 Elasticsearch 的文本检索特性和预先计算的 PageRank 值，对查询结果进行综合排序。代码中，`/search` 路由提供了站内查询、短语查询、通配查询，以及个性化排序等高级特性。另外，`/api/query_documents` 提供了对文档附件的查询，`/api/query_history` 与 `/api/snapshots` 提供了查询日志和网页快照功能。

在代码实现中，主要思路包括：

### 6.1**向量空间模型与链接分析（PageRank）**：

 在 `search` 接口中使用了 Elasticsearch 的 `function_score` 查询，将 `_score`（基于TF-IDF的向量空间模型打分）与页面的 `pagerank` 字段值相加作为最终排序分值。
 示例代码（摘自 `search` 路由中的查询构造部分）：

```python
"function_score": {
    "query": query_body,
    "script_score": {
        "script": {
            "source": "_score + doc['pagerank'].value"
        }
    },
    "boost_mode": "replace"
}
```

在此基础上，TF-ID F 得分与 PageRank 相结合，使得既与查询相关、又在链接分析中具有较高权值的页面排序更靠前。

### 6.2**提供多种高级搜索功能：**

#### 6.2.1 站内查询

站内查询是最基本的查询功能，对站内已索引的网页进行全文搜索。
 实现方式：

- 在 `/search` 路由中，如果用户不指定文件类型、不进行通配或短语查询等特殊参数，默认即为普通的站内全文查询操作。
- 使用 Elasticsearch 的 `multi_match` 查询在 `title`, `content`, `url`, `publisher`, `source` 等多字段中检索用户输入的 `query`。
   代码片段（简化后）：

```python
must_clauses.append({
    "multi_match": {
        "query": query,
        "fields": ["title", "content", "url", "publisher", "source"],
        "type": "best_fields",
        "operator": "and"
    }
})
```

#### 6.2.2 文档查询

对站内附件（如 `doc/docx、pdf、xls/xlsx`）的查询，通过对 `attachments` 字段进行过滤实现。
 实现方式：

- 用户在查询参数中指定 `file_type`，后端在 ES 查询中通过 `nested` 查询过滤符合要求的附件类型。
- 路由 `/api/query_documents` 专门实现文档查询，根据用户输入的 `doc_type` 和 `query` 字段检索包含相应附件的页面。

代码片段（来自 `/api/query_documents` 路由）：

```python
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
    }
}
```

#### 6.2.3 短语查询

短语查询支持对多个Term进行严格的匹配顺序和相邻性约束。例如“南开大学”与“南开是一所综合性大学”的查询区别。
 实现方式：

- 前端在调用 `/search` 接口时增加 `phrase=true` 参数。
- 后端在must_clauses中使用 `multi_match` 查询的 `"type": "phrase"` 来确保按照短语匹配。
   代码片段：

```python
if phrase:
    must_clauses.append({
        "multi_match": {
            "query": query,
            "type": "phrase",
            "fields": ["title^2", "content"],
            "slop": 2
        }
    })
```

#### 6.2.4 通配查询

通配查询允许用户使用 `*` 和 `?` 等通配符进行模糊匹配。例如“温*”可匹配“温家宝”、“温斯顿”等。
 实现方式：

- 在 `/search` 接口中通过 `wildcard=true` 参数进行控制。
- 若用户查询中包含 `*` 或 `?`，则构建通配符查询（`wildcard` 查询）。
- 为避免性能问题，禁止前导通配符（检查查询的首字符）。
   代码片段：

```python
if wildcard and ("*" in query or "?" in query):
    if query.startswith("*") or query.startswith("?"):
        return jsonify({"error": "前导通配符会导致性能问题，请避免使用"}), 400
    
    # 构建通配符查询
    wildcard_query_body = build_function_score_query(build_wildcard_query(query))
    res = es.search(index="web_pages", body=wildcard_query_body)
```

#### 6.2.5 查询日志

系统在用户每次查询时，将查询条件、时间戳、搜索次数等信息存储在 MySQL 数据库中。
 实现方式：

- 在 `log_query_to_database` 函数中对 `SearchHistory` 模型进行增量更新或插入。
- 用户可通过 `/api/query_history` 接口获取自己所有的查询历史。

代码片段：

```python
# 存储查询日志
log_query_to_database(
    user_id=user_id,
    query=query,
    search_mode=search_mode,
    file_type=file_type if file_type else None,
    sort_field=sort_field if sort_field else None,
    sort_order=sort_order
)

# 获取查询日志
@app.route("/api/query_history", methods=["GET"])
@login_required
def query_history():
    histories = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.timestamp.desc()).all()
    ...
```

#### 6.2.6 网页快照

网页快照功能是将用户的查询结果（链接列表）以快照形式保存在数据库中，用户可后续查看当时的搜索快照，即使网页内容已更新或消失。
 实现方式：

- 在 `/search` 接口处理查询结果后，调用 `save_snapshot` 函数将当前查询的 URL 列表以 JSON 字符串形式存储在 `Snapshot` 表中。
- 用户可通过 `/api/snapshots` 查看所有快照，`/api/snapshots/<id>` 查看特定快照，支持删除快照。

代码片段：

```python
# 保存搜索快照
def save_snapshot(user_id, query, results):
    snapshot = Snapshot(user_id=user_id, search_query=query, results=json.dumps(results, ensure_ascii=False))
    db.session.add(snapshot)
    db.session.commit()

# 查看快照列表
@app.route("/api/snapshots", methods=["GET"])
@login_required
def list_snapshots():
    snapshots = Snapshot.query.filter_by(user_id=user_id).order_by(Snapshot.timestamp.desc()).all()
    ...
```

### 6.3个性化查询

在当前代码中，个性化查询主要体现在对用户兴趣关键词的处理和结果排序中：

- 在 `/search` 方法中，根据用户最近的 20 条搜索记录提取关键词（`get_user_interests` 函数），将这些关键词作为 `should` 子句增加查询的权重，提升与用户兴趣相关的文档排名。
- 不同用户登录后会有不同的搜索历史和偏好，因此相同的查询在不同用户登录下可能返回不同排序的结果，从而实现初步的个性化排序。

代码片段（个性化查询示意）：

```python
user_interests = get_user_interests(user_id)
if user_interests:
    for interest in user_interests:
        should_clauses.append({
            "match": {
                "content": {
                    "query": interest,
                    "boost": 2
                }
            }
        })
```

通过上述处理方式，系统在查询时不仅考虑用户提交的查询词，还加入用户的历史兴趣偏好，使对用户更相关的结果排序更靠前，从而实现基本的个性化查询。

------

综上，本系统通过 `/search`、`/api/query_documents`、`/api/query_history`、`/api/snapshots` 等API，实现了站内查询、文档查询、短语查询、通配查询、查询日志、网页快照共计六种高级搜索功能，并结合向量空间模型与链接分析（PageRank）对检索结果进行排序，同时利用用户历史兴趣实现初步的个性化查询。

## 7. web界面

### 用户登录界面

<img src="./image-20241216221005578.png" alt="image-20241216221005578" style="zoom: 33%;" />

### 用户注册界面

<img src="./image-20241216221114142.png" alt="image-20241216221114142" style="zoom:33%;" />

### 用户查询页面

![image-20241216221156931](./image-20241216221156931.png)

#### 查询日志

![image-20241216221233490](./image-20241216221233490.png)

#### 网页快照及查看快照

![image-20241216221300748](./image-20241216221300748.png)

![image-20241216221332136](./image-20241216221332136.png)

#### 个性化推荐

![image-20241216221425716](./image-20241216221425716.png)

#### 查询结果

![image-20241216221531721](./image-20241216221531721.png)

## 8.个性化推荐

本系统中个性化推荐主要选择了“搜索上的联想关联”，通过结合用户历史搜索记录与实时输入的部分查询词，为用户提供动态的搜索建议。这种方式能够在用户输入查询条件的过程中，基于其历史行为与已有的网页数据，联想出更符合其兴趣和习惯的搜索结果候选项，从而实现一定程度的个性化推荐。

### 实现思路

1. **用户历史行为分析**：
    系统在用户每次进行搜索时，都会将搜索记录存储在 MySQL 数据库的 `SearchHistory` 表中，包括查询词、搜索时间、搜索次数等信息。当用户再次输入查询时，系统可根据其历史搜索记录提取与当前输入相关的词条作为建议。这种关联推荐基于用户自身的历史行为，实现初步的个性化联想。
2. **实时联想补全**：
    在用户输入部分查询词 `partial_query` 时，系统会：
   - 首先从用户历史搜索中寻找包含 `partial_query` 的查询记录，并根据搜索次数（`search_count`）降序排列，取出前若干条作为潜在候选。
   - 对这些候选查询词再次在 Elasticsearch 中进行检索，若找到匹配页面（如标题中有该查询词），则将该页面的 `title` 和 `url` 作为联想推荐返回给用户。
   - 如果历史记录不足以满足候选数量，则直接使用 `partial_query` 在 Elasticsearch 中进行 `phrase_prefix` 查询，寻找与该前缀匹配的页面，补足建议数量。
3. **个性化体现**：
    不同用户具有不同的搜索历史。当用户已登录并查询时，`/api/search_suggestions` 接口会根据该用户的专属搜索历史数据库记录为其提供独特的联想建议。这样，每个用户会得到不尽相同的、与自身历史搜索行为相吻合的联想推荐，从而实现初步的个性化。

### 关键代码分析

以下为 `search_suggestions` 接口的核心实现逻辑（节选自后端代码）：

```python
@app.route("/api/search_suggestions", methods=["GET"])
@login_required
def search_suggestions():
    user_id = session['user_id']
    partial_query = request.args.get("q", "").strip()

    if not partial_query:
        return jsonify({"suggestions": []}), 200

    suggestions = []
    seen_titles_urls = set()

    # 1. 基于用户的历史查询构建推荐
    historical_queries = SearchHistory.query.filter(
        SearchHistory.user_id == user_id,
        SearchHistory.search_query.ilike(f"%{partial_query}%")
    ).order_by(SearchHistory.search_count.desc()).limit(10).all()

    for entry in historical_queries:
        search_query = entry.search_query
        # 构建对ES的查询, 查找与search_query相关的网页
        suggest_query = {
            "size": 1,
            "query": {
                "multi_match": {
                    "query": search_query,
                    "fields": ["title", "content"]
                }
            },
            "sort": [{"_score": {"order": "desc"}}]
        }

        res = es.search(index="web_pages", body=suggest_query)
        for hit in res['hits']['hits']:
            title = hit['_source'].get('title', '').strip()
            url = hit['_source'].get('url', '').strip()
            if title and url and (title, url) not in seen_titles_urls:
                suggestions.append({"title": title, "url": url})
                seen_titles_urls.add((title, url))
                break
        if len(suggestions) >= 5:
            break

    # 2. 若不足5条建议，用实时前缀匹配补齐
    if len(suggestions) < 5:
        remaining = 5 - len(suggestions)
        direct_suggest_query = {
            "size": remaining,
            "query": {
                "multi_match": {
                    "query": partial_query,
                    "fields": ["title^3", "content"],
                    "type": "phrase_prefix"
                }
            },
            "sort": [{"_score": {"order": "desc"}}]
        }

        res = es.search(index="web_pages", body=direct_suggest_query)
        for hit in res['hits']['hits']:
            title = hit['_source'].get('title', '').strip()
            url = hit['_source'].get('url', '').strip()
            if title and url and (title, url) not in seen_titles_urls:
                suggestions.append({"title": title, "url": url})
                seen_titles_urls.add((title, url))
                if len(suggestions) >= 5:
                    break

    return jsonify(suggestions), 200
```

通过上述代码：

- 当用户在搜索框中输入部分关键词时，系统先查找该用户过去的搜索记录中是否有匹配的查询，以此找到相关的页面作为建议。用户的历史记录越丰富、查询次数越高，对应的建议结果也越精确与个性化。
- 若历史建议不够，则使用当前输入作为前缀，直接在ES中使用 `phrase_prefix` 搜索进一步补全结果。
- 返回给用户的 suggestions 包含页面标题和URL，帮助用户快速跳转到可能感兴趣的内容。

### 效果与总结

通过结合用户历史搜索记录与实时联想搜索，本系统在用户尚未完成输入查询时，即可提供多条潜在相关结果建议。这些建议不仅基于全局索引数据，也受用户过去搜索行为影响，从而体现个性化推荐的价值。

此方法简单高效，有助于用户在不明确目标时获得启发，也能在明确目标时更快速地找到相关内容。虽然此处的实现仍较为基础，但已经达到了个性化推荐中“搜索联想关联”的初步目标，为后续进一步的内容分析与更高级的个性化推荐功能打下基础。

## 9.如何运行该项目

在本系统的后端架构中，使用了三个较为重要的工具，分别为Redis、MySQL 和 Elasticsearch (ES) ，它们各自扮演了不同的角色，以实现高效的用户管理、查询记录存储、全文搜索和推荐功能。下面结合代码和实际用途加以说明：

1. **MySQL 的作用**：
    在代码中，MySQL 是通过 `SQLAlchemy` 来访问和管理的关系型数据库，用于存储与用户账号、历史搜索记录、聊天历史、网页快照等结构化数据相关的信息。
    具体而言：

   - **用户信息（User表）**：存储用户名、密码哈希等用户账号数据，便于用户注册、登录、认证和后续的个性化服务。
   - **搜索历史（SearchHistory表）**：记录用户每次的查询条件、查询时间、搜索次数、文件类型过滤等信息，方便后续展示用户查询日志、统计用户兴趣偏好以及实现个性化推荐。
   - **网页快照（Snapshot表）**：将用户进行搜索时生成的网页链接列表以JSON字符串形式存档，用户可事后查看历史搜索时的页面状态（网页快照）。

   因此，MySQL 承担了**结构化数据存储与管理**的任务，为用户管理、搜索日志、个性化推荐和页面快照功能提供可靠的数据支撑。

2. **Redis 的作用**：
    在本系统中，Redis 作为一种内存级的键值存储，用于**会话（Session）管理和缓存**。如果检测到 `REDIS_URL` 环境变量，则会将 Flask 的 Session 存储类型设定为 Redis。
    其主要作用在于：

   - 将用户会话数据（如 `user_id`、`username`）存储在 Redis 中，以比文件系统或数据库更快的读写速度来提供用户状态管理（如登录状态维持、会话过期管理）。
   - 利用 Redis 的内存级数据存储特性，可快速响应用户请求，提高用户体验。

   简言之，Redis 在此框架中**负责快速、高效的会话数据缓存与管理**，提高系统的可扩展性和响应速度。

3. **Elasticsearch (ES) 的作用**：
    Elasticsearch 是一款分布式搜索和分析引擎，适用于全文搜索、模糊查询、通配符查询和复杂搜索场景。在本代码中，ES 的主要用途是：

   - **全文索引与检索**：对先前已抓取并解析的网页（包括标题、正文、附件链接、图片等数据）建立索引，以支持站内查询、文档查询、短语查询和通配查询。
   - **排序与打分**：通过 `function_score` 将 TF-IDF(向量空间模型) 与已预计算的 PageRank 值相结合，对搜索结果进行综合排序，让更有价值或更权威的页面排在前面。
   - **联想推荐和建议**：在用户输入部分查询词时，可利用 Elasticsearch 的前缀匹配、通配符匹配和多字段匹配，快速给出潜在的相关查询建议。这也是实现个性化推荐的一部分，因为推荐结果同时参考用户的历史行为。

   因此，ES 的主要作用是**高效的全文搜索与复杂查询支持**，通过丰富的查询 DSL 和脚本评分机制实现多样化、高性能的搜索功能以及高级的排序策略。

综上所述：

- **MySQL**：用于存储和管理结构化数据（用户、搜索历史、快照），确保用户信息和查询日志的持久化和可追溯性。
- **Redis**：用于快速管理会话数据，提供高效的临时数据存储和用户状态维护。
- **Elasticsearch**：用于全文索引和搜索，支持多种查询类型和打分机制，实现站内搜索、短语查询、通配查询、文档搜索以及个性化联想推荐等高级搜索功能。

因此要想运行该代码，需要先打开ES![image-20241216222356452](./image-20241216222356452.png)

然后是redis

![image-20241216222427596](./image-20241216222427596.png)

最后是由于代码中使用了**SQLAlchemy** 数据模型（Model）定义，当使用 **Flask-SQLAlchemy** 创建和维护数据库模型时，模型的结构（如字段类型、表名、关系等）是代码层面的定义，而数据库中的表结构则是存储层面的实体。一旦项目开发过程中对 **模型定义** 进行了变更，比如添加新字段、修改字段类型、删除字段等，数据库中的表结构也必须进行同步更新。但这些变更不能直接通过 SQLAlchemy 进行自动同步，因此需要 **Flask-Migrate** 结合 **Alembic** 生成和管理迁移脚本。

**初始化迁移环境**： 在你的项目根目录下，运行：

```bash
flask db init
```

这会在你的项目中创建一个 `migrations` 文件夹，内部包含数据库迁移所需的版本管理文件。

**自动生成迁移脚本**：
当你对模型（Model）进行更改后（例如新增字段或修改字段类型），使用下面的命令自动生成迁移脚本：

```bash
flask db migrate -m "描述你的更改"
```

`-m` 后的字符串为对此次迁移的描述。

**应用迁移到数据库**：
当迁移脚本生成后，执行：

```bash
flask db upgrade
```

该命令会根据迁移脚本中记录的变更对实际数据库结构进行升级，从而让数据库与最新的模型定义保持一致。

当然前提是你的**mysql**数据库已经正常运行了，当这些准备工作都完成之后，运行**app.py**文件后，这个信息检索系统就会运行在http://localhost:5000网站下。

