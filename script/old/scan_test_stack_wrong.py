import subprocess
import json
import os
import time
import pickle

# 全局缓存目录
CACHE_DIR = os.path.join(os.path.dirname(__file__), "../cache")
os.makedirs(CACHE_DIR, exist_ok=True)

def run_command(command, max_retries=5):
    """运行系统命令并返回结果，带有重试机制"""
    retry_count = 1
    while retry_count <= max_retries:
        print(f"运行命令: {command} (重试次数: {retry_count})")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if 'TIMEOUT' not in result.stdout:
            break
        retry_count += 1
        time.sleep(5)
    return result.stdout, result.stderr

def cache_filename(domain):
    """生成缓存文件名"""
    return os.path.join(CACHE_DIR, f"{domain.replace('.', '_')}.cache")

def load_cache(domain):
    """加载缓存"""
    file_path = cache_filename(domain)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            print(f"从缓存中加载: {file_path}")
            return pickle.load(f)
    return None

def save_cache(domain, data):
    """保存缓存"""
    file_path = cache_filename(domain)
    with open(file_path, 'wb') as f:
        print(f"保存到缓存: {file_path}")
        pickle.dump(data, f)

def dfs_adns_path_alookup(domain, ns, nsip, path):
    """深度优先搜索查询域名A记录路径的非递归实现"""
    print(f"查询域名: {domain}, NS: {ns}, NSIP: {nsip}, PATH: {path}")
    # 尝试加载缓存
    cached_result = load_cache(domain)
    if cached_result:
        return cached_result
    
    stack = [(domain, ns, nsip, path)]
    paths = []
    visited = set()

    while stack:
        print(f"堆栈状态: {stack}")
        current_domain, current_ns, current_nsip, current_path = stack.pop()
        current_path = current_path + [(current_ns, current_nsip)]
        print(f"当前路径: {current_path}")

        # 检查是否已经访问过
        if (current_ns, current_nsip) in visited:
            continue
        visited.add((current_ns, current_nsip))

        # 构造查询命令
        command = f"echo {current_domain} | zdns A --name-servers={current_nsip}"
        output, err = run_command(command)
        
        # 解析命令输出
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            print(f"解析JSON失败: {output}")
            continue
        
        if 'data' in data:
            data = data['data']
            
            # 检查是否有 "answers" 键
            if 'answers' in data and data['answers']:
                answer = data['answers'][0]['answer']
                paths.append(current_path)
                result = (answer, paths)
                save_cache(domain, result)
                return result
            
            # 检查 "additionals" 键
            if 'additionals' in data and data['additionals']:
                for additional in data['additionals']:
                    if additional['type'] == 'A':
                        next_ns = additional['name']
                        next_nsip = additional['answer']
                        if (next_ns, next_nsip) not in visited:
                            stack.append((current_domain, next_ns, next_nsip, current_path))
                            print(f"添加到堆栈: {next_ns}, {next_nsip}")

            # 检查 "authorities" 键
            if 'authorities' in data and data['authorities']:
                for authority in data['authorities']:
                    next_ns = authority['answer']
                    if (next_ns, '192.58.128.30') not in visited:
                        stack.append((next_ns, 'j.root-servers.net', '192.58.128.30', []))
                        print(f"添加到堆栈: {next_ns}, j.root-servers.net, 192.58.128.30")
                        for wait_path in paths:
                            stack.append((current_domain, next_ns, wait_path[-1][1], current_path))
                            print(f"添加到堆栈: {current_domain}, {next_ns}, {wait_path[-1][1]}")
    
    if not paths:
        paths.append(current_path)
    result = (None, paths)
    save_cache(domain, result)
    return result

# 测试函数
if __name__ == "__main__":
    domain = '1.unique.001.uniquefortest.online'
    ns = 'j.root-servers.net'
    nsip = '192.58.128.30'
    path = []
    
    answer, path_diagram = dfs_adns_path_alookup(domain, ns, nsip, path)
    
    print("A记录查询结果:", answer)
    print("遍历路径:", path_diagram)
