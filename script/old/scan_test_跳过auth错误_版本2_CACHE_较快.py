import subprocess
import json
import time
import copy
import os

# 全局缓存 TODO:在cache文件夹下开pkl文件存储CACHE，方便多线程之间共享？但是每个线程之间CACHE不一样，怎么办？
# 解决方案：现在的方案是一个CACHE:CACHE[nsip][domain] = output，需要把这个CACHE改成多个CACHEip，以nsip命名对应的pkl文件，根据ip来读取对应的CACHEip，每次读取之前开线程锁，读取完之后释放线程锁。
CACHE = {}
ROOT = 'j.root-servers.net'

# CACHE_DIR = os.path.join(os.path.dirname(__file__), "../cache")
# os.makedirs(CACHE_DIR, exist_ok=True)
OUTPUT_DIR = os.path.dirname(__file__)+"/../output/adns_path/"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_command(command, max_retries=1, timeout=10):
    """运行系统命令并返回结果，带有重试机制"""
    retry_count = 1
    command += " --timeout=" + str(timeout)
    while retry_count <= max_retries:
        print(f"运行命令: {command} (重试次数: {retry_count})")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if 'TIMEOUT' not in result.stdout:
            break
        retry_count += 1
        #time.sleep(1)
    #print(f"命令输出: {result.stdout}")
    return result.stdout, result.stderr

def dfs_adns_path_alookup(domain, ns, nsip, path, all_paths):
    """深度优先搜索查询域名A记录路径"""
    global CACHE

    #print(f"查询域名: {domain}, NS: {ns}, NSIP: {nsip}, PATH: {path}")

    current_path = path + [(ns, nsip)]
    #print(f"当前路径: {current_path}")
    if nsip in CACHE and domain in CACHE[nsip]:
        #print("\n命中缓存！\n")
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
        recv_data = json.loads(output)
    except json.JSONDecodeError:
        # 解析失败，说明没有返回正常回答
        print(f"解析JSON失败: {output}")
        new_path = copy.deepcopy(current_path)
        new_path.append((domain, '$NOJSON$'))
        all_paths.append(new_path)
        print(f"最终路径：{str(new_path)}\n")
        #解析失败也要加到缓存里，因为重试解析失败是更多时间资源浪费
        return

    if 'data' in recv_data:
        data = recv_data['data']
        data_status = recv_data['status']
        if data_status != 'NOERROR':
            # 返回状态不正常，结束递归
            print(f"返回状态不正常: {data_status}")
            new_path = copy.deepcopy(current_path)
            new_path.append((domain, f'$NOIP_{data_status}$'))
            all_paths.append(new_path)
            print(f"最终路径：{str(new_path)}\n")
            return

        # 检查是否有 "answers" 键
        if 'answers' in data and data['answers']:
            # 找到A记录，结束递归
            answers = list()
            for answer_dict in data['answers']:
                if answer_dict['type'] == 'A':
                    answers.append(answer_dict['answer'])
                elif answer_dict['type'] == 'CNAME':
                    answers.append(answer_dict['answer'])
            for ip in answers:
                new_path = copy.deepcopy(current_path)
                new_path.append((domain, ip))
                all_paths.append(new_path)
                #print("\n完成查询。")
                #print(f"最终路径：{str(new_path)}\n")
            return #递归返回后 all_paths[-1]即为上一层递归函数需要的ADNS 的 ns, nsip (或者直接是最后需要的answer)

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
                    #print(f"处理additionals: {next_ns}, {next_nsip}")
                    dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path, all_paths)
        
        #print(f"胶水记录集合：{str(glue_set)}")
        # 检查 "authorities" 键
        if 'authorities' in data and data['authorities']:
            have_auth_flag = False
            for authority in data['authorities']:
                if authority['type'] == 'NS': 
                    have_auth_flag = True
                    next_ns = authority['answer']
                    if next_ns in glue_set: continue
                    print(f"处理authorities: {next_ns}")
                    # 需要查询权威服务器的A记录
                    glueless_query_all_paths = list()
                    dfs_adns_path_alookup(next_ns, ROOT, '192.58.128.30', [], glueless_query_all_paths)
                    for glueless_query_path in glueless_query_all_paths:
                        next_ns, next_nsip = glueless_query_path[-1]
                        
                        if next_nsip.startswith('$') or not next_nsip:
                            print(f"authorities向下递归错误，返回路径错误")
                            new_path = copy.deepcopy(current_path)
                            new_path.append(glueless_query_path)
                            all_paths.append(new_path)
                            print(f"最终路径：{str(new_path)}\n")
                            return

                        new_path = copy.deepcopy(current_path)
                        new_path.append(glueless_query_path)
                        dfs_adns_path_alookup(domain, next_ns, next_nsip, new_path, all_paths)

                elif authority['type'] == 'SOA' and not have_auth_flag: #只有SOA记录，且没有NS记录
                    print(f"处理authorities SOA: {data}")
                    new_path = copy.deepcopy(current_path)
                    new_path.append((domain, '$SOA$'))
                    all_paths.append(new_path)
                    print(f"最终路径：{str(new_path)}\n")

                    


# 测试函数
if __name__ == "__main__":
    domain = '1.unique.001.uniquefortest.online'
    # domain = 'www.tsinghua.edu.cn'
    domain = 'www.czu.cn'
    # domain = 'www.itp.ac.cn'
    # domain = 'www.cib.com.cn'
    # domain = 'www.faw-vw.com'
    # domain = 'www.vipshop.com'
    # domain = 'vipshop.com'
    # domain = '1.unique.001.uniquefortest.online'

    ns = ROOT
    nsip = '192.58.128.30'
    path = []
    all_paths = []

    dfs_adns_path_alookup(domain, ns, nsip, path, all_paths)

    DATETIME = time.strftime("%Y%m%d-%H%M", time.localtime())
    
    with open(f"{OUTPUT_DIR}{DATETIME}_{domain}.txt", 'w') as f:
        json.dump(all_paths, f, indent=4)
        # for path in all_paths:
        #     f.write(str(path) + '\n')
