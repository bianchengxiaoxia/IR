import json

# 定义要查找的字符串
TARGET_STRING = "aiguo..nankai"

def remove_links_from_json(file_path):
    # 读取 JSON 文件
    with open(file_path, 'r', encoding='utf-8') as file:
        links = json.load(file)

    # 使用列表推导式，过滤掉包含特定字符串的链接
    updated_links = [link for link in links if TARGET_STRING not in link]

    # 保存修改后的 JSON 数据
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(updated_links, file, indent=4, ensure_ascii=False)

    print(f"已删除包含 '{TARGET_STRING}' 的链接，更新后的文件已保存。")



# 输入 JSON 文件路径
file_path = 'visited_links.json'  # 替换为你的 JSON 文件路径
remove_links_from_json(file_path)
