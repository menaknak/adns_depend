import os
import pickle

DATE = '20240106'
CACHE_DIR = os.path.dirname(__file__) + "/../cache/" + DATE

def load_cache(domain):
    """从文件加载缓存"""
    cache_file = os.path.join(CACHE_DIR, f"{domain}.cache")
    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            return pickle.load(f)
    return []

def load_cache2txt(domain):
    """从文件加载缓存，并保存为txt文件"""
    cache_content = load_cache(domain)
    txt_dir = os.path.join(CACHE_DIR, "txt")
    os.makedirs(txt_dir, exist_ok=True)
    txt_file = os.path.join(txt_dir, f"{domain}.txt")
    with open(txt_file, 'w', encoding='utf-8') as f:
        for item in cache_content:
            f.write(str(item) + '\n')

domains = ['ns.sia.cn','es.sia.ac.cn']
for domain in domains:
    load_cache2txt(domain)  
