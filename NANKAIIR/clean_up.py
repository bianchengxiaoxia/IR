import os
import shutil

# 文件和文件夹路径
visited_links_file = "visited_links.json"
scraped_pages_dir = "scraped_pages"


def cleanup():
    # 删除 visited_links.json 文件
    if os.path.exists(visited_links_file):
        try:
            os.remove(visited_links_file)
            print(f"Deleted file: {visited_links_file}")
        except Exception as e:
            print(f"Error deleting file {visited_links_file}: {e}")

    # 删除 scraped_pages 文件夹
    if os.path.exists(scraped_pages_dir):
        try:
            shutil.rmtree(scraped_pages_dir)
            print(f"Deleted directory: {scraped_pages_dir}")
        except Exception as e:
            print(f"Error deleting directory {scraped_pages_dir}: {e}")

    # 重新创建 scraped_pages 文件夹
    try:
        os.mkdir(scraped_pages_dir)
        print(f"Recreated directory: {scraped_pages_dir}")
    except Exception as e:
        print(f"Error creating directory {scraped_pages_dir}: {e}")


if __name__ == "__main__":
    cleanup()
