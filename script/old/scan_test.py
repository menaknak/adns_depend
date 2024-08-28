import subprocess
import json
import time
import copy

# 全局缓存
CACHE = {}
ROOT = 'j.root-servers.net'

def run_command(command, max_retries=5):
    """运行系统命令并返回结果，带有重试机制"""
    retry_count = 1
    while retry_count <= max_retries:
        print(f"运行命令: {command} (重试次数: {retry_count})")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if 'TIMEOUT' not in result.stdout:
            break
        retry_count += 1
        time.sleep(1)
    print(f"命令输出: {result.stdout}")
    return result.stdout, result.stderr

def dfs_adns_path_alookup(domain, ns, nsip, path, all_paths):
    """深度优先搜索查询域名A记录路径"""
    global CACHE

    print(f"查询域名: {domain}, NS: {ns}, NSIP: {nsip}, PATH: {path}")

    current_path = path + [(ns, nsip)]
    print(f"当前路径: {current_path}")
    if nsip in CACHE and domain in CACHE[nsip]:
        print("\n命中缓存！\n")
        output = CACHE[nsip][domain]
    else:
        # 构造查询命令
        command = f"echo {domain} | zdns A --name-servers={nsip}"
        output, err = run_command(command)
        if nsip not in CACHE:
            CACHE[nsip] = dict()
        CACHE[nsip][domain] = output

    # 解析命令输出
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        # 解析失败，说明没有返回正常回答
        print(f"解析JSON失败: {output}")
        data = {}
        # TODO：在current_path上加一个特殊符号$，表示路径已经在这里终止了，它需要表现得像answers，一直加$,直到递归到最后一层$


    if 'data' in data:
        data = data['data']

        # 检查是否有 "answers" 键
        if 'answers' in data and data['answers']:
            # 找到A记录，结束递归
            answers = list()
            for answer_dict in data['answers']:
                if answer_dict['type'] != 'A': continue
                answers.append(answer_dict['answer'])
            for ip in answers:
                new_path = copy.deepcopy(current_path)
                new_path.append((domain, ip))
                all_paths.append(new_path)
                print("\n完成查询。")
                print(f"最终路径：{str(new_path)}\n")
            return

        # 检查 "additionals" 键
        glue_set = set()
        if 'additionals' in data and data['additionals']:
            for additional in data['additionals']:
                if additional['type'] == 'A':
                    next_ns = additional['name'] 
                    glue_set.add(next_ns)
                    if not next_ns.endswith('.'): glue_set.add(next_ns + '.')
                    else: glue_set.add(next_ns[:-1])
                    next_nsip = additional['answer']
                    print(f"处理additionals: {next_ns}, {next_nsip}")
                    dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path, all_paths)
        
        print(f"胶水记录集合：{str(glue_set)}")
        # 检查 "authorities" 键
        if 'authorities' in data and data['authorities']:
            for authority in data['authorities']:
                next_ns = authority['answer']
                if next_ns in glue_set: continue
                print(f"处理authorities: {next_ns}")
                # 需要查询权威服务器的A记录
                nest_all_paths = list()
                dfs_adns_path_alookup(next_ns, ROOT, '192.58.128.30', [], nest_all_paths)
                for nest_path in nest_all_paths:
                    new_path = copy.deepcopy(current_path)
                    new_path.append(nest_path)
                    next_ns, next_nsip = nest_path[-1]
                    dfs_adns_path_alookup(domain, next_ns, next_nsip, new_path, all_paths)


# 测试函数
if __name__ == "__main__":
    domain = '1.unique.001.uniquefortest.online'
    # domain = 'www.tsinghua.edu.cn'
    ns = ROOT
    nsip = '192.58.128.30'
    path = []
    all_paths = []

    dfs_adns_path_alookup(domain, ns, nsip, path, all_paths)

    print(all_paths)
