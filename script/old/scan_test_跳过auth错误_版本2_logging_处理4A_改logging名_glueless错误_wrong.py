import subprocess
import json
import time
import copy
import os
import logging

# 配置日志记录
DATETIME = time.strftime("%Y%m%d-%H%M%S", time.localtime())
LOG_DIR = os.path.dirname(__file__) + "/../output/error/"
os.makedirs(LOG_DIR, exist_ok=True)

# 全局缓存
CACHE = {}
ROOT = 'j.root-servers.net'

OUTPUT_DIR = os.path.dirname(__file__) + "/../output/adns_path/"
os.makedirs(OUTPUT_DIR, exist_ok=True)



def run_command(command, max_retries=1, timeout=10):
    """运行系统命令并返回结果，带有重试机制"""
    retry_count = 1
    command += " --timeout=" + str(timeout)
    while retry_count <= max_retries:
        logging.debug(f"运行命令: {command} (重试次数: {retry_count})\n")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if 'TIMEOUT' not in result.stdout:
            break
        retry_count += 1
    logging.debug(f"命令输出: {result.stdout}\n")
    return result.stdout, result.stderr

def log_final_path(new_path):
    """将最终路径写入单独的日志文件"""
    with open(mid_output_file, 'a') as log_file:
        log_file.write(str(new_path) + '\n')

def dfs_adns_path_alookup(domain, ns, nsip, path, all_paths, depth=0):
    """深度优先搜索查询域名A记录路径"""
    global CACHE

    prefix = f"D{depth} "
    logging.debug(f"{prefix}查询域名: {domain}, NS: {ns}, NSIP: {nsip}, PATH: {path}\n")

    current_path = path + [(ns, nsip)]
    logging.debug(f"{prefix}当前路径: {current_path}\n")
    if nsip in CACHE and domain in CACHE[nsip]:
        logging.debug(f"{prefix}命中缓存！\n")
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
        logging.error(f"{prefix}解析JSON失败: {output}\n")
        new_path = copy.deepcopy(current_path)
        new_path.append((domain, '$NOJSON'))
        all_paths.append(new_path)
        log_final_path(new_path)
        return
    except RecursionError:
        logging.error(f"{prefix}Maximum recursion depth exceeded\n")
        return

    if 'data' in recv_data:
        data = recv_data['data']
        data_status = recv_data['status']
        if data_status != 'NOERROR':
            # 返回状态不正常，结束递归
            logging.debug(f"{prefix}返回状态不正常: {data_status}\n")
            new_path = copy.deepcopy(current_path)
            new_path.append((domain, f'$NOIP_{data_status}'))
            all_paths.append(new_path)
            log_final_path(new_path)
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
                logging.debug(f"{prefix}完成查询。\n")
                log_final_path(new_path)
            return

        # 检查 "additionals" 键
        glue_set = set()
        if 'additionals' in data and data['additionals']:
            for additional in data['additionals']:
                if additional['type'] == 'AAAA': #暂时不处理AAAA记录，但是要加到glue_set中，以免authorities里循环请求
                    next_ns = additional['name']
                    glue_set.add(next_ns)
                    if not next_ns.endswith('.'):
                        glue_set.add(next_ns + '.')
                    else:
                        glue_set.add(next_ns[:-1])                   
                elif additional['type'] == 'A':
                    next_ns = additional['name']
                    glue_set.add(next_ns)
                    if not next_ns.endswith('.'):
                        glue_set.add(next_ns + '.')
                    else:
                        glue_set.add(next_ns[:-1])
                    next_nsip = additional['answer']
                    logging.debug(f"{prefix}处理additionals: {next_ns}, {next_nsip}\n")
                    try:
                        dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path, all_paths, depth+1)
                    except RecursionError:
                        logging.error(f"{prefix}Maximum recursion depth exceeded during additionals processing\n")
                        return

        # 检查 "authorities" 键
        if 'authorities' in data and data['authorities']:
            have_auth_flag = False
            for authority in data['authorities']:
                if authority['type'] == 'NS':
                    have_auth_flag = True
                    next_ns = authority['answer']
                    if next_ns in glue_set:
                        continue
                    logging.debug(f"{prefix}处理authorities: {next_ns}\n")
                    # 需要查询权威服务器的A记录
                    glueless_query_all_paths = list()
                    try:
                        dfs_adns_path_alookup(next_ns, ROOT, '192.58.128.30', [], glueless_query_all_paths, depth+1)
                    except RecursionError:
                        logging.error(f"{prefix}Maximum recursion depth exceeded during authorities processing\n")
                        return
                    for glueless_query_path in glueless_query_all_paths:
                        next_ns, next_nsip = glueless_query_path[-1]

                        if next_nsip.startswith('$') or not next_nsip:
                            logging.error(f"{prefix}authorities向下递归错误，返回路径错误\n")
                            new_path = copy.deepcopy(current_path)
                            new_path.append(glueless_query_path)
                            all_paths.append(new_path)
                            log_final_path(new_path)
                            return

                        new_path = copy.deepcopy(current_path)
                        new_path.append(glueless_query_path)
                        try:
                            dfs_adns_path_alookup(domain, next_ns, next_nsip, new_path, all_paths, depth+1)
                        except RecursionError:
                            logging.error(f"{prefix}Maximum recursion depth exceeded during authorities processing\n")
                            return

                elif authority['type'] == 'SOA' and not have_auth_flag: #只有SOA记录，且没有NS记录
                    logging.debug(f"{prefix}处理authorities SOA: {data}\n")
                    new_path = copy.deepcopy(current_path)
                    new_path.append((domain, '$SOA'))
                    all_paths.append(new_path)
                    log_final_path(new_path)


# 测试函数
if __name__ == "__main__":
    domain = '1.unique.001.uniquefortest.online'
    domain = 'www.tsinghua.edu.cn'
    # domain = 'www.czu.cn'
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
    # 重新配置日志记录以包含域名
    logging_output_file = f"{LOG_DIR}{DATETIME}_{domain}_logging.txt"
    logging.basicConfig(filename=logging_output_file, level=logging.DEBUG, format='%(message)s')

    # 中途输出文件路径
    mid_output_file = f"{OUTPUT_DIR}{DATETIME}_{domain}_midoutput-paths.txt"

    try:
        dfs_adns_path_alookup(domain, ns, nsip, path, all_paths)
    except RecursionError:
        logging.error("Maximum recursion depth exceeded in main")

    with open(f"{OUTPUT_DIR}{DATETIME}_{domain}_json.txt", 'w') as f:
        json.dump(all_paths, f, indent=4)