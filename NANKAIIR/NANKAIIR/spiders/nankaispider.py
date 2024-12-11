import scrapy
from scrapy.http import Request
from bs4 import BeautifulSoup, NavigableString
import os
import json
import re
from elasticsearch import Elasticsearch, helpers
import networkx as nx
import urllib3
import hashlib
import logging
from urllib.parse import urlparse, urljoin

# 导入必要的异常类
from scrapy.spidermiddlewares.httperror import HttpError
from twisted.internet.error import DNSLookupError, TimeoutError, TCPTimedOutError, ConnectionRefusedError

# 定义常量
DOMAIN_NAME = "cc.nankai.edu.cn"

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NankaiSpider(scrapy.Spider):
    name = "nankai_spider"
    allowed_domains = ["nankai.edu.cn"]
    start_urls = ["https://cc.nankai.edu.cn"]

    # 爬取限制与存储目录
    max_valid_pages = 100000  # 最大有效爬取页面数量
    save_dir = "scraped_pages"  # 保存网页内容的目录
    visited_links_file = "visited_links.json"  # 保存已访问链接的文件

    # 最小内容长度
    MIN_CONTENT_LENGTH = 40  # 根据需要调整

    def __init__(self, *args, **kwargs):
        super(NankaiSpider, self).__init__(*args, **kwargs)
        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir, exist_ok=True)

        # 初始化访问过的链接集合
        self.visited_links = set()
        if os.path.exists(self.visited_links_file):
            try:
                with open(self.visited_links_file, "r", encoding="utf-8") as f:
                    self.visited_links = set(json.load(f))
            except Exception as e:
                self.logger.error(f"加载已访问链接失败: {e}")
                self.visited_links = set()
        self.valid_page_count = self.count_saved_files()

        # 初始化 Elasticsearch 客户端
        self.es = Elasticsearch(
            hosts=["https://localhost:9200"],
            basic_auth=("elastic", "aWVrracnZiMZZDMLJ-fq"),
            verify_certs=False  # 自签名证书环境下使用
        )

        # 检查 Elasticsearch 是否运行
        try:
            if not self.es.ping():
                self.log("无法连接到 Elasticsearch，请检查配置。")
                raise ConnectionError("Elasticsearch 连接失败")
        except Exception as e:
            self.log(f"Elasticsearch 连接错误: {e}")
            raise e

        # 初始化 NetworkX 有向图
        self.graph = nx.DiGraph()

        # 存储已成功索引的URL
        self.indexed_urls = set()

        # 初始化索引缓冲区
        self.es_bulk = []
        self.bulk_size = 100  # 设置批量索引的大小，根据需求调整

        # 测试文件写入权限
        try:
            test_file = os.path.join(self.save_dir, "test_permission.txt")
            with open(test_file, "w") as f:
                f.write("测试写入权限")
            os.remove(test_file)
            self.logger.info("文件写入权限验证成功。")
        except Exception as e:
            self.logger.error(f"文件写入权限验证失败: {e}")
            raise e

    def count_saved_files(self):
        """
        计算保存目录中已保存的 JSON 文件数量。
        """
        count = 0
        for root, dirs, files in os.walk(self.save_dir):
            for file in files:
                if file.endswith('.json'):
                    count += 1
        self.log(f"已保存文件数量: {count}")
        return count

    def start_requests(self):
        for url in self.start_urls:
            yield Request(
                url,
                callback=self.parse,
                errback=self.errback_httpbin,
            )

    def errback_httpbin(self, failure):
        # Log 错误
        self.logger.error(repr(failure))

        # Add the failed URL to visited_links to prevent retries
        if failure.check(HttpError):
            response = failure.value.response
            self.logger.error(f"HTTP 错误 {response.status} on {response.url}")
            self.visited_links.add(response.url)
        elif failure.check(DNSLookupError):
            request = failure.request
            self.logger.error(f"DNS 查找失败: {request.url}")
            self.visited_links.add(request.url)
        elif failure.check(TimeoutError, TCPTimedOutError):
            request = failure.request
            self.logger.error(f"请求超时: {request.url}")
            self.visited_links.add(request.url)
        elif failure.check(ConnectionRefusedError):
            request = failure.request
            self.logger.error(f"连接被拒绝: {request.url}")
            self.visited_links.add(request.url)
        else:
            request = failure.request
            self.logger.error(f"未知错误 on {request.url}: {failure}")
            self.visited_links.add(request.url)

        # 保存已访问链接
        self.save_visited_links()

    def parse(self, response):
        self.logger.info(f"正在解析: {response.url}")

        if response.status != 200:
            self.logger.warning(f"Skipping {response.url} due于 status code {response.status}")
            self.visited_links.add(response.url)
            self.save_visited_links()
            return

        if self.valid_page_count >= self.max_valid_pages:
            self.logger.info("已达到目标文件数，正在关闭爬虫...")
            self.crawler.engine.close_spider(self, "达到最大有效爬取页面数，爬虫中断")
            return

        if response.url in self.visited_links:
            self.logger.debug(f"URL 已访问: {response.url}")
            return

        # 检查响应类型是否为文本类型（如 text/html）
        content_type = response.headers.get('Content-Type', b'').decode().lower()
        if 'text' not in content_type:
            self.log(f"Non-text response detected at {response.url}, Content-Type: {content_type}. Skipping...")
            self.visited_links.add(response.url)
            self.save_visited_links()
            return

        self.visited_links.add(response.url)

        # 使用 BeautifulSoup 解析网页内容
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")

        # 提取标题
        title = soup.title.get_text(strip=True) if soup.title else "无标题"
        safe_title = re.sub(r"[\/:*?\"<>|]", "_", title)
        self.logger.debug(f"页面标题: {title}")

        # 提取正文内容
        content = self.extract_main_content(soup, response.url)

        # 定义正则模式（根据实际网页情况调整）
        patterns = {
            "publisher": re.compile(r"发布者[:：]\s*(.+)", re.IGNORECASE),
            "source": re.compile(r"来源[:：]\s*(.+)", re.IGNORECASE),
            "views": re.compile(r"(?:浏览次数|浏览人数|浏览量|阅读次数|阅读)\s*[:：]\s*(\d+)", re.IGNORECASE),
            "publish_time": re.compile(
                r"(?:发布时间|时间)[:：]\s*(\d{4}[-/年]\d{1,2}[-/月]\d{1,2}(?:日)?)",
                re.IGNORECASE
            )
        }

        # 初始化字段
        publisher = "未知"
        source = "未知"
        views = None
        publish_time = "未知"

        # 提取并移除 publisher
        pub_match = patterns["publisher"].search(content)
        if pub_match:
            publisher = pub_match.group(1).strip()
            content = patterns["publisher"].sub("", content, count=1)
            self.logger.debug(f"发布者: {publisher}")

        # 提取并移除 source
        src_match = patterns["source"].search(content)
        if src_match:
            source = src_match.group(1).strip()
            content = patterns["source"].sub("", content, count=1)
            self.logger.debug(f"来源: {source}")

        # 提取并移除 views
        views_match = patterns["views"].search(content)
        if views_match:
            views = int(views_match.group(1))
            content = patterns["views"].sub("", content, count=1)
            self.logger.debug(f"浏览次数: {views}")

        # 提取并移除 publish_time
        pt_match = patterns["publish_time"].search(content)
        if pt_match:
            raw_publish_time = pt_match.group(1)
            publish_time = self.normalize_publish_time(raw_publish_time)
            content = patterns["publish_time"].sub("", content, count=1)
            self.logger.debug(f"发布时间: {publish_time}")
        else:
            # 如果未在 content 中找到 publish_time，尝试从页面其他部分提取
            publish_time_element = soup.find(
                string=re.compile(r"(?:发布时间|发稿时间|时间)[:：]\s*\d{4}[-/年]\d{1,2}[-/月]\d{1,2}(?:日)?", re.IGNORECASE))
            if publish_time_element:
                match_date = re.search(r"(?:发布时间|发稿时间|时间)[:：]\s*(\d{4}[-/年]\d{1,2}[-/月]\d{1,2}(?:日)?)",
                                       publish_time_element, re.IGNORECASE)
                if match_date:
                    raw_publish_time = match_date.group(1)
                    publish_time = self.normalize_publish_time(raw_publish_time)

                    # 从父元素中移除 publish_time 的文本
                    parent = publish_time_element.parent
                    if parent:
                        parent_text = parent.get_text()
                        parent_text_cleaned = patterns["publish_time"].sub("", parent_text, count=1)
                        if parent.string is not None:
                            parent.string.replace_with(parent_text_cleaned)
                        else:
                            parent.clear()
                            parent.append(parent_text_cleaned)
                    self.logger.debug(f"发布时间（从其他部分提取）: {publish_time}")

        # 再次清理多余空行和空格
        content = re.sub(r"\n\s*\n", "\n", content).strip()

        # 提取图片链接
        images = []
        for img in soup.find_all("img", src=True):
            img_src = img["src"]
            img_src = response.urljoin(img_src)
            images.append(img_src)

        # 提取附件链接
        attachments = []
        # 修改后的正则表达式，匹配文件类型并捕获文件类型
        attachment_pattern = re.compile(r"\.(docx?|pdf|xls[x]?)$", re.IGNORECASE)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            # 转为绝对路径
            file_url = response.urljoin(href)
            match = attachment_pattern.search(href)
            if match:
                # 附件名称为链接文本，若无文本则用文件名代替
                name = a.get_text(strip=True)
                if not name:
                    name = os.path.basename(href)
                file_type = match.group(1).lower()  # 获取文件类型并转为小写
                attachments.append({"name": name, "url": file_url, "type": file_type})
                self.logger.debug(f"提取到附件: {name}, 类型: {file_type}, URL: {file_url}")

        # 在content中提取联系人、电话、邮箱、地址等信息
        contact_info = {}
        # 匹配联系人
        contact_person_match = re.search(r"(联系人[:：]\s*([^\n]+))", content)
        if contact_person_match:
            contact_info["contact_person"] = contact_person_match.group(2).strip()
            content = content.replace(contact_person_match.group(1), "")
            self.logger.debug(f"联系人: {contact_info['contact_person']}")

        # 匹配电话
        phone_match = re.search(r"(电话[:：]?\s*(\d{3,4}[-\s]?\d{7,8}|\d{11}))", content)
        if phone_match:
            contact_info["phone"] = phone_match.group(2).strip()
            content = content.replace(phone_match.group(1), "")
            self.logger.debug(f"电话: {contact_info['phone']}")

        # 匹配邮箱
        email_match = re.search(
            r"(?i)(?:邮箱|email)[:：]?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*(?:邮箱|email)?",
            content
        )

        if email_match:
            # 检查哪个组匹配成功
            if email_match.group(1):
                contact_info["email"] = email_match.group(1).strip()
                content = content.replace(email_match.group(0), "")
                self.logger.debug(f"邮箱: {contact_info['email']}")
            elif email_match.group(2):
                contact_info["email"] = email_match.group(2).strip()
                content = content.replace(email_match.group(2), "")
                self.logger.debug(f"邮箱: {contact_info['email']}")

        # 匹配地址
        address_match = re.search(r"(地址[:：]\s*([^\n]+))", content)
        if address_match:
            contact_info["address"] = address_match.group(2).strip()
            content = content.replace(address_match.group(1), "")
            self.logger.debug(f"地址: {contact_info['address']}")

        # 若content中还有多余空行，继续清理
        content = re.sub(r"\n\s*\n", "\n", content).strip()

        # 判断内容长度，如果少于MIN_CONTENT_LENGTH字则不保存
        if len(content.replace("\n", "").strip()) < self.MIN_CONTENT_LENGTH:
            self.logger.info(f"内容长度不足，未保存: {response.url}")
            # 保存已访问链接并继续
            self.save_visited_links()
            # 提取并爬取新的链接
            for link in self.extract_links(soup, response):
                yield Request(
                    link,
                    callback=self.parse,
                    errback=self.errback_httpbin,
                )
            return

        # 保存内容条件判断
        # 增加一个更严格的日期模式匹配
        if re.search(r"/\d{4}/\d{2,4}/", response.url) and content:
            # 生成唯一文件名以避免重复
            unique_id = hashlib.md5(response.url.encode()).hexdigest()
            file_name = os.path.join(self.save_dir, f"{safe_title}_{unique_id}.json")
            os.makedirs(os.path.dirname(file_name), exist_ok=True)
            page_data = {
                "title": title,
                "url": response.url,
                "publish_time": publish_time,
                "content": content,
                "images": images,
                "links": self.extract_links(soup, response),
                "publisher": publisher,
                "source": source,
                "views": views,
                "attachments": attachments,
                "contact_info": contact_info if contact_info else None
            }

            try:
                with open(file_name, "w", encoding="utf-8") as f:
                    json.dump(page_data, f, ensure_ascii=False, indent=4)
                self.logger.info(f"保存成功: {file_name}")

                # 仅在成功保存文件后才增加计数
                self.valid_page_count += 1

                # 检查是否达到最大保存数量
                if self.valid_page_count >= self.max_valid_pages:
                    self.logger.info("已达到目标文件数，正在关闭爬虫...")
                    self.crawler.engine.close_spider(self, "达到最大有效爬取页面数，爬虫中断")
            except Exception as e:
                self.log(f"保存文件失败 {file_name}: {e}")
            else:
                # 保存到 Elasticsearch
                self.index_to_elasticsearch(page_data)

        # 保存已访问链接
        self.save_visited_links()

        # 更新图数据
        self.graph.add_node(response.url)
        for link in self.extract_links(soup, response):
            if link not in self.visited_links:
                self.graph.add_edge(response.url, link)

        # 遍历链接继续爬取
        for link in self.extract_links(soup, response):
            if link not in self.visited_links:
                yield Request(
                    link,
                    callback=self.parse,
                    errback=self.errback_httpbin,
                )

    def extract_links(self, soup, response):
        links = []
        date_pattern = re.compile(r"/\d{4}/\d{2,4}/")  # 匹配 /YYYY/MM/ 或 /YYYY/MMDD/ 等

        for a in soup.find_all("a", href=True):
            href = a["href"]
            # 将相对URL转换为绝对URL
            if not href.startswith("http://") and not href.startswith("https://"):
                href = response.urljoin(href)
            parsed_url = urlparse(href)
            netloc = parsed_url.netloc.lower()
            path = parsed_url.path.lower()

            # 排除身份验证相关的路径
            if 'idp/profile/saml2/redirect/sso' in path:
                continue

            # 确保域名以 'nankai.edu.cn' 结尾
            if DOMAIN_NAME in netloc:
                # 检查路径中是否包含日期信息
                if date_pattern.search(path):
                    if href not in self.visited_links:
                        links.append(href)
                else:
                    # 如果不包含日期信息，仍然可以添加链接以便发现更多日期链接
                    if href not in self.visited_links:
                        links.append(href)

        self.logger.debug(f"提取到的链接数量: {len(links)}")
        return links

    def extract_main_content(self, soup, url):
        """
        提取页面的主要内容，使用多种策略以提高准确性。
        """
        # 尝试使用 <article> 标签
        articles = soup.find_all("article")
        if articles:
            self.logger.debug(f"找到 {len(articles)} 个 <article> 标签。")
            # 选择包含最多文本的 <article> 标签
            main_article = max(articles, key=lambda a: len(a.get_text(strip=True)))
            return main_article.get_text("\n", strip=True)

        # 如果没有 <article> 标签，尝试多个 <div> 类名
        candidates = []
        class_patterns = re.compile(r"(content|article|main|text|post|entry|body)", re.IGNORECASE)
        divs = soup.find_all("div", class_=class_patterns)
        for div in divs:
            text = div.get_text("\n", strip=True)
            if text:
                candidates.append((div, len(text)))

        if candidates:
            # 选择文本最多的 <div>
            main_div = max(candidates, key=lambda x: x[1])[0]
            self.logger.debug(f"选择包含最多文本的 <div> 类名: {main_div.get('class')}")
            return main_div.get_text("\n", strip=True)

        # 如果上述方法均失败，使用整个 <body> 标签
        body = soup.body
        if body:
            self.logger.debug("使用整个 <body> 标签作为主要内容。")
            return body.get_text("\n", strip=True)

        # 如果没有 <body> 标签，返回空字符串
        self.logger.warning(f"未能提取到主要内容，URL: {url}")
        return ""

    def normalize_publish_time(self, raw_time):
        # 将 publish_time 标准化为 'yyyy-MM-dd' 格式
        normalized_time = raw_time.replace("年", "-").replace("月", "-").replace("日", "")
        normalized_time = normalized_time.replace("/", "-")
        parts = normalized_time.split("-")
        if len(parts) == 3:
            year, month, day = parts
            year = year.strip()
            month = month.strip().zfill(2)
            day = day.strip().zfill(2)
            normalized_time = f"{year}-{month}-{day}"
            return normalized_time
        else:
            return "未知"

    def index_to_elasticsearch(self, data):
        try:
            action = {
                "_index": "web_pages",
                "_id": data["url"],  # 使用 URL 作为唯一 ID
                "_source": data
            }
            self.es_bulk.append(action)
            self.logger.debug(f"添加到 Elasticsearch 索引缓冲区: {data['url']}")

            # 当缓冲区达到批量大小时，执行批量索引
            if len(self.es_bulk) >= self.bulk_size:
                helpers.bulk(self.es, self.es_bulk, raise_on_error=False)
                self.logger.info(f"批量索引成功: {len(self.es_bulk)} 个文档")
                self.indexed_urls.update([doc["_id"] for doc in self.es_bulk])
                self.es_bulk = []  # 清空缓冲区
        except Exception as e:
            self.log(f"批量索引到 Elasticsearch 失败: {e}")

    def save_visited_links(self):
        try:
            with open(self.visited_links_file, "w", encoding="utf-8") as f:
                json.dump(list(self.visited_links), f, ensure_ascii=False, indent=4)
            self.logger.debug("已访问链接已保存。")
        except Exception as e:
            self.logger.error(f"保存已访问链接失败: {e}")

    def closed(self, reason):
        # 处理剩余的缓冲区
        if self.es_bulk:
            try:
                helpers.bulk(self.es, self.es_bulk, raise_on_error=False)
                self.logger.info(f"批量索引成功: {len(self.es_bulk)} 个文档")
                self.indexed_urls.update([doc["_id"] for doc in self.es_bulk])
                self.es_bulk = []
            except Exception as e:
                self.log(f"批量索引到 Elasticsearch 失败: {e}")

        self.log("开始计算 PageRank...")
        self.log(f"图中节点数量: {self.graph.number_of_nodes()}")
        self.log(f"图中边数量: {self.graph.number_of_edges()}")
        try:
            pagerank = nx.pagerank(self.graph, alpha=0.85)
            for url, rank in pagerank.items():
                if url in self.indexed_urls:
                    try:
                        self.es.update(
                            index="web_pages",
                            id=url,
                            body={"doc": {"pagerank": float(rank)}}
                        )
                        self.log(f"已更新 PageRank: {url} = {rank}")
                    except Exception as e:
                        self.log(f"更新 PageRank 失败: {url} - {e}")
        except Exception as e:
            self.log(f"计算 PageRank 失败: {e}")

        # 检查是否所有文件都已索引
        total_files = self.count_saved_files()
        if len(self.indexed_urls) < total_files:
            self.log(f"警告: 有 {total_files - len(self.indexed_urls)} 个文件未成功索引到 Elasticsearch.")
            # 可选：重新尝试索引未索引的文件
