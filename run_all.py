import subprocess
import sys
import os

# 获取当前脚本所在的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 定义要依次运行的脚本列表
scripts = ["NANKAIIR/clean_up.py","ES_FIND.py", "ES_DEL.py",]

for script in scripts:
    script_path = os.path.join(current_dir, script)
    if not os.path.exists(script_path):
        print(f"脚本 {script} 不存在，请检查路径！")
        sys.exit(1)

    # 运行脚本，指定编码为utf-8，避免UnicodeDecodeError
    print(f"正在运行脚本: {script}")
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        encoding='utf-8',  # 指定编码
        errors='replace'  # 遇到无法解码的字符时替换，避免报错
    )

    # 如果标准输出为空，则打印“无输出”
    stdout_text = result.stdout.strip() if result.stdout else ""
    if not stdout_text:
        stdout_text = "无输出"

    # 如果标准错误为空，则打印“无输出”
    stderr_text = result.stderr.strip() if result.stderr else ""
    if not stderr_text:
        stderr_text = "无输出"

    # 输出脚本的标准输出与标准错误
    print("标准输出:", stdout_text)
    print("标准错误:", stderr_text)

    # 检查执行结果，如果返回码不为0则退出
    if result.returncode != 0:
        print(f"运行 {script} 时出现错误，返回码为 {result.returncode}")
        sys.exit(result.returncode)

print("所有脚本已依次运行完成。")
