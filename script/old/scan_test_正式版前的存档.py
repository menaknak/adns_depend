import subprocess
import json
import time

# 全局缓存
CACHE = {}

def run_command(command, max_retries=5):
    """运行系统命令并返回结果，带有重试机制"""
    retry_count = 1
    while retry_count <= max_retries:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if 'TIMEOUT' not in result.stdout:
            break
        retry_count += 1
        time.sleep(5)
    return result.stdout, result.stderr

def dfs_adns_path_alookup(domain, ns, nsip, path):
    """深度优先搜索查询域名A记录路径"""
    global CACHE

    # 如果已经在缓存中，直接返回缓存结果
    if domain in CACHE:
        return CACHE[domain]

    # 记录当前路径
    current_path = path + [(ns, nsip)]

    # 构造查询命令
    command = f"echo {domain} | zdns A --name-servers={nsip}"
    output, err = run_command(command)

    # 解析命令输出
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        data = {}

    if 'data' in data:
        data = data['data']

        # 检查是否有 "answers" 键
        if 'answers' in data and data['answers']:
            answer = data['answers'][0]['answer']
            path_diagram = current_path
            CACHE[domain] = (answer, path_diagram)
            return answer, path_diagram

        # 检查 "additionals" 键
        if 'additionals' in data and data['additionals']:
            for additional in data['additionals']:
                if additional['type'] == 'A':
                    next_ns = additional['name']
                    next_nsip = additional['answer']
                    return dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path)

        # 检查 "authorities" 键
        if 'authorities' in data and data['authorities']:
            for authority in data['authorities']:
                next_ns = authority['answer']
                # 需要查询权威服务器的A记录
                wait_nsip, wait_path = dfs_adns_path_alookup(next_ns, 'j.root-servers.net', '192.58.128.30', [])
                if wait_nsip:
                    sub_answer, sub_path = dfs_adns_path_alookup(domain, next_ns, wait_nsip, [])
                    if sub_answer:
                        combined_path = current_path + [wait_path] + sub_path
                        CACHE[domain] = (sub_answer, combined_path)
                        return sub_answer, combined_path

    # 如果没有找到答案，返回None
    CACHE[domain] = (None, current_path)
    return None, current_path

# 测试函数
if __name__ == "__main__":
    domain = '1.unique.001.uniquefortest.online'
    ns = 'j.root-servers.net'
    nsip = '192.58.128.30'
    path = []

    answer, path_diagram = dfs_adns_path_alookup(domain, ns, nsip, path)

    print("A记录查询结果:", answer)
    print("遍历路径:", path_diagram)
