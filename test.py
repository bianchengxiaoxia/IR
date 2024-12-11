import re

pattern = re.compile(r"(?:浏览次数|浏览人数|浏览量|阅读次数|阅读)\s*[:：]\s*(\d+)\b", re.IGNORECASE)
text = "浏览次数：39"
match = pattern.search(text)
if match:
    print("匹配成功:", match.group(1))
else:
    print("未匹配")
