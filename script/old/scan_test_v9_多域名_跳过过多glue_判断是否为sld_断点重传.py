import subprocess
import json
import copy
import os
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import tldextract
import time
from tqdm import tqdm

MAX_VENDOR_COUNT = 2
MAX_DEPTH = 20
MAX_PATH_COUNT = 1000

# 用于记录进度的检查点文件
CHECKPOINT_FILE = os.path.dirname(__file__) + "/checkpoint.txt"

# 配置日志记录
DATE = (datetime.now()).strftime("%Y%m%d")

LOG_DIR = os.path.dirname(__file__) + "/../output/error/"+DATE+"/"
LOG_DIR = os.path.dirname(__file__) + "/../output/error/"
os.makedirs(LOG_DIR, exist_ok=True)

# 全局缓存
ROOT = 'j.root-servers.net'

OUTPUT_DIR = os.path.dirname(__file__) + "/../output/adns_path/"+DATE+"/"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_sld(fqdn):
    result = tldextract.extract(fqdn)
    sld = f"{result.domain}.{result.suffix}"
    return sld

def extract_vendor(fqdn):
    result = tldextract.extract(fqdn)
    sld = f"{result.domain}"
    return sld

def save_checkpoint(current_target):
    with open(CHECKPOINT_FILE, 'w') as f:
        f.write(f"{DATE} {INPUTPATH} {current_target}")

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            return f.read().strip().split()
    return None, None, None


def load_data(filename):
    if 'txt' in filename or 'csv' in filename or 'json' in  filename:
        ip_list=[]
        with open(filename,'r') as f:
            ip_list=f.readlines()
        return [i.strip() for i in ip_list]
    else:
        import pickle
        with open(filename,'rb') as f:
            return pickle.load(f)

def run_command(command, max_retries=0, timeout=5):
    """运行系统命令并返回结果，带有重试机制"""
    retry_count = 0 
    command += " --timeout=" + str(timeout)
    while retry_count <= max_retries:
        logging.debug(f"运行命令: {command} (重试次数: {retry_count})\n")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if 'TIMEOUT' not in result.stdout:
            break
        retry_count += 1
    logging.debug(f"命令输出: {result.stdout}\n")
    return result.stdout, result.stderr

# def log_final_path(new_path):
#     """将最终路径写入单独的日志文件"""
#     with open(mid_output_file, 'a') as log_file:
#         log_file.write(str(new_path) + '\n')

def dfs_adns_path_alookup(domain, ns, nsip, path, all_paths, onpath_domain_ns_list,cache,depth=0):
    """深度优先搜索查询域名A记录路径"""

    prefix = f"D{depth} "
    logging.debug(f"{prefix}查询域名: {domain}, NS: {ns}, NSIP: {nsip}, PATH: {path}\n")

    if depth > MAX_DEPTH:
        logging.error(f"{prefix} {domain}递归深度超过{MAX_DEPTH}！\n")
        new_path = copy.deepcopy(path)
        new_path.append((domain, '$DEPTH$',domain))
        all_paths.append(new_path)
        return
        #log_final_path(new_path)

    if len(all_paths) > MAX_PATH_COUNT:
        logging.error(f"{prefix} {domain}路径数量超过{MAX_PATH_COUNT}！\n")
        return
    
    current_path = path + [(ns, nsip ,domain)]
    current_onpath_domain_ns_list = onpath_domain_ns_list+[(domain, ns)]

    logging.debug(f"{prefix}当前路径: {current_path}\n")

    # 判断循环依赖
    if len(current_onpath_domain_ns_list) > len(set(current_onpath_domain_ns_list)): # 说明最后一个加入的 queryname,ADNShostname 组合 与之前的重复了。为什么不看IP？其实跟IP没有关系，主要是ADNShostname它自己就无法解析，陷入了循环。我们不应该向同一个NS查询同一个域名两次。
        logging.error(f"{prefix} {domain}循环依赖！")
        logging.info(f"{prefix}current_onpath_domain_ns_list: {current_onpath_domain_ns_list}")

        new_path = copy.deepcopy(current_path)
        new_path.append((domain, '$LOOP$',domain))
        all_paths.append(new_path)
        logging.info(f"{prefix}new_path: {new_path}")
        logging.info(f"{prefix}domain: {domain}\n")
        return
        #log_final_path(new_path)
        

    # 检查缓存
    if nsip in cache and domain in cache[nsip]:
        logging.debug(f"{prefix}命中缓存！\n")
        output = cache[nsip][domain]
    else:
        # 构造查询命令
        command = f"echo {domain} | zdns A --name-servers={nsip}"
        output, err = run_command(command)
        if nsip not in cache:
            cache[nsip] = dict()
        cache[nsip][domain] = output

    # 解析命令输出
    try:
        recv_data = json.loads(output)
    except json.JSONDecodeError:
        # 解析失败，说明没有返回正常回答
        logging.error(f"{prefix} {domain}解析JSON失败: {output}\n")
        new_path = copy.deepcopy(current_path)
        new_path.append((domain, '$NOJSON$',domain))
        all_paths.append(new_path)
        return
        #log_final_path(new_path)
        
    except RecursionError:
        logging.error(f"{prefix} {domain}Maximum recursion depth exceeded\n")
        

    if 'data' in recv_data:
        data = recv_data['data']
        data_status = recv_data['status']
        if data_status != 'NOERROR':
            # 返回状态不正常，结束递归
            logging.debug(f"{prefix}返回状态不正常: {data_status}\n")
            new_path = copy.deepcopy(current_path)
            new_path.append((domain, f'$NOIP_{data_status}$',domain))
            all_paths.append(new_path)
            #log_final_path(new_path)

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
                new_path.append((domain, ip,domain))
                all_paths.append(new_path)
                logging.debug(f"{prefix}完成查询。\n")
                #log_final_path(new_path)
            return

        # 检查 "additionals" 键
        glue_set = set()
        # glue_vendor_count 用来计数一个vendor被用作几次glue，如果超过2次，就不再进一步递归
        glue_vendor_count = defaultdict(int)
        if 'additionals' in data and data['additionals']:
            for additional in data['additionals']:
                if additional['type'] == 'AAAA': #暂时不处理AAAA记录，但是要加到glue_set中，以免authorities里循环请求
                    next_ns = additional['name']
                    next_ns_vendor = extract_vendor(next_ns)
                    #glue_vendor_count[next_ns_vendor] += 1 # 这里先不限制2，因为现在只处理A记录
                    glue_set.add(next_ns)
                    if not next_ns.endswith('.'):
                        glue_set.add(next_ns + '.')
                    else:
                        glue_set.add(next_ns[:-1])                   
                elif additional['type'] == 'A':
                    next_ns = additional['name']
                    next_ns_vendor = extract_vendor(next_ns)
                    glue_vendor_count[next_ns_vendor] += 1
                    glue_set.add(next_ns)
                    if glue_vendor_count[next_ns_vendor] <= MAX_VENDOR_COUNT: # 这里还没有加CDN域名限制
                        if not next_ns.endswith('.'): glue_set.add(next_ns + '.')
                        else: glue_set.add(next_ns[:-1])
                        
                        next_nsip = additional['answer']
                        logging.debug(f"{prefix}处理additionals: {next_ns}, {next_nsip}\n")
                        try:
                            dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path, all_paths, current_onpath_domain_ns_list, cache,depth+1)
                        except RecursionError:
                            logging.error(f"{prefix} {domain}Maximum recursion depth exceeded during additionals processing\n")

        # 检查 "authorities" 键
        if 'authorities' in data and data['authorities']:
            have_auth_flag = False
            for authority in data['authorities']:
                if authority['type'] == 'NS':
                    have_auth_flag = True
                    next_ns = authority['answer']
                    next_ns_vendor = extract_vendor(next_ns)
                    glue_vendor_count[next_ns_vendor] += 1
                    if next_ns in glue_set or glue_vendor_count[next_ns_vendor] > MAX_VENDOR_COUNT:
                        continue
                    logging.debug(f"{prefix}处理authorities: {next_ns}\n")
                    # 需要查询权威服务器的A记录
                    glueless_query_all_paths = list()
                    # glueless_query_onpath_domain_ns_list = list()
                    try:
                        dfs_adns_path_alookup(next_ns, ROOT, '192.58.128.30', [], glueless_query_all_paths, current_onpath_domain_ns_list, cache,depth+1)
                    except RecursionError:
                        logging.error(f"{prefix} {domain}Maximum recursion depth exceeded during authorities processing\n")
                    for glueless_query_path in glueless_query_all_paths:

                        
                        next_ns, next_nsip,_ = glueless_query_path[-1]
                        if next_nsip.startswith('$') or not next_nsip:
                            logging.error(f"{prefix} {domain}authorities向下递归错误")
                            logging.info(f"{prefix}glueless_query_path: {glueless_query_path}")

                            new_path = copy.deepcopy(current_path)
                            new_path.append(glueless_query_path)
                            new_path.append((domain, '$$$',domain)) # 加上终止符号，表示这个路径被前面分支无法解析而提前终止。
                            all_paths.append(new_path)
                            logging.info(f"{prefix}new_path: {new_path}")
                            logging.info(f"{prefix}domain: {domain}\n")
                            # log_final_path(new_path)
                        else:
                            new_path = copy.deepcopy(current_path)
                            new_path.append(glueless_query_path)
                            try:
                                dfs_adns_path_alookup(domain, next_ns, next_nsip, new_path, all_paths, current_onpath_domain_ns_list, cache,depth+1)
                            except RecursionError:
                                logging.error(f"{prefix} {domain}Maximum recursion depth exceeded during authorities processing\n")

                elif authority['type'] == 'SOA' and not have_auth_flag: #只有SOA记录，且没有NS记录
                    logging.debug(f"{prefix}处理authorities SOA: {data}\n")
                    new_path = copy.deepcopy(current_path)
                    new_path.append((domain, '$SOA$',domain))
                    all_paths.append(new_path)              
                    #log_final_path(new_path)


# 测试函数
if __name__ == "__main__":
    
    # INPUTPATH = os.path.dirname(__file__) + "/../input/domain_list.txt"
    INPUTPATH = '/home/nly/DNS/adns_depend/input/tranco1M_gov_edu_test_domain.csv'
    # INPUTPATH = '/home/nly/DNS/adns_depend/input/test_2_sld.txt'
    # INPUTPATH = '/home/nly/DNS/adns_depend/input/test_1_sld.txt'
    domain_list = load_data(INPUTPATH)
    # 重新配置日志记录以包含域名
    logging_output_file = f"{LOG_DIR}{DATE}_logging.txt"
    logging.basicConfig(filename=logging_output_file, level=logging.WARNING, format='%(message)s')


    checkpoint_date,checkpoint_inputpath, checkpoint_target = load_checkpoint()
    if  checkpoint_date != DATE or checkpoint_inputpath != INPUTPATH:
        # 已经不是今天的查询，检查点无效，清空检查点
        checkpoint_target = None



    print(f"开始查询，检查点: {checkpoint_target}")
    skip = bool(checkpoint_target)
    count = 0


    begin_time = time.time()
    for domain in tqdm(domain_list):
        if skip:
            if domain == checkpoint_target:
                print(f"找到检查点: {checkpoint_target}，从此处继续...")
                skip = False
            continue
        
        if domain == extract_sld(domain):
            query_domain = 'www.' + domain
        
        DATETIME = time.strftime("%Y%m%d-%H%M%S", time.localtime())


        ns = ROOT
        nsip = '192.58.128.30'
        path = []
        all_paths = []
        onpath_domain_ns_list = []
        cache = {}


        try:
            dfs_adns_path_alookup(query_domain, ns, nsip, path, all_paths, onpath_domain_ns_list,cache)
        except RecursionError:
            logging.error("Maximum recursion depth exceeded in main")
        with open(f"{OUTPUT_DIR}{DATETIME}_{query_domain}_allpaths.json", 'w') as f:
            for path in all_paths:
                f.write(str(path) + '\n')
            # json.dump(all_paths, f, indent=4)
            # json.dump(all_paths, f)
        save_checkpoint(domain)
    
    end_time = time.time()
    # 打印所需时分秒，需要格式化为时分秒
    print(f"Total time: {timedelta(seconds=end_time-begin_time)}")
    


      

