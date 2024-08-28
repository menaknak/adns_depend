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
import ipaddress
import pickle
import threading
import queue
import threading
from threading import Lock

thread_num = 10

MAX_SLD_COUNT = 2
MAX_VENDOR_COUNT = 100 #100相当于不限制
MAX_DEPTH = 10
MAX_PATH_COUNT = 1000
IF_TLDADNS_DFS = False
LOGGING_LEVEL = logging.ERROR
q = queue.Queue() # 工作队列，用于线程资源调度
mutex1 = Lock()
mutex2 = Lock()

# 配置日志记录
DATE = (datetime.now()).strftime("%Y%m%d")+f'-限制depth{MAX_DEPTH}'
# DATE = f'20240401-限制depth{MAX_DEPTH}'

ROOT = 'j.root-servers.net'
ROOTIP = '192.58.128.30'


# INPUTPATH = os.path.dirname(__file__) + "/../input/domain_list.txt"
INPUTPATH = '/home/nly/DNS/adns_depend/input/tranco1M_gov_edu_test_domain.csv'
# INPUTPATH = '/home/nly/DNS/adns_depend/input/重点域名14860_20231230.txt'
INPUTPATH = '/home/nly/DNS/adns_depend/input/重点域名6766_20240127_ssl证书-去外企.txt'
# INPUTPATH = '/home/nly/DNS/adns_depend/input/loopindataset_20240108.txt'
# INPUTPATH = '/home/nly/DNS/adns_depend/input/wufabreak_20240823.txt'


suf = INPUTPATH.split('/')[-1].split('_')[0]

# 用于记录进度的检查点文件
CHECKPOINT_FILE = os.path.dirname(__file__) + "/checkpoint.txt"




# LOG_DIR = os.path.dirname(__file__) + "/../output/error/"+DATE+"/"+suf+"/"
# LOG_DIR = os.path.dirname(__file__) + "/../output/error/"+suf+"/"
LOG_DIR = os.path.dirname(__file__) + "/../output/error/"+DATE+"/"
os.makedirs(LOG_DIR, exist_ok=True)

OUTPUT_DIR = os.path.dirname(__file__) + "/../output/adns_path/"+DATE+"/"+suf+"/"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 文件系统全局缓存路径
CACHE_DIR = os.path.dirname(__file__) + "/../cache/"+DATE
os.makedirs(CACHE_DIR, exist_ok=True)

def validate_ip(ip):
    try:
        # 尝试解析为IPv4地址
        ipaddress.IPv4Address(ip)
        return "ipv4"
    except ipaddress.AddressValueError:
        pass

    try:
        # 尝试解析为IPv6地址
        ipaddress.IPv6Address(ip)
        return "ipv6"
    except ipaddress.AddressValueError:
        pass

    # 如果都解析失败，则返回notip
    return "notip"

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

def save_cache(nsip,domain, cmd_ouput):
    """保存缓存到文件"""
    cache_file = os.path.join(CACHE_DIR, f"{nsip}-{domain}.txt")
    with open(cache_file, 'w', encoding="utf-8") as f:
        f.write(cmd_ouput)


def load_cache(nsip,domain):
    """从文件加载缓存"""
    cache_file = os.path.join(CACHE_DIR, f"{nsip}-{domain}.txt")
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return f.read()
    return ''

def load_data(filename):
    if 'txt' in filename or 'csv' in filename or 'json' in  filename:
        ip_list=[]
        with open(filename,'r') as f:
            ip_list=f.readlines()
        return [i.strip() for i in ip_list]
    else:
        with open(filename,'rb') as f:
            return pickle.load(f)

def run_command(command, max_retries=1, timeout=10):
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

def stripdot(string):
    if string.endswith('.'):
        return string[:-1].lower()
    else:
        return string.lower()

def dfs_adns_path_alookup(domain, ns, nsip, path, all_paths, onpath_domain_ns_list, cache, depth=0):
    """深度优先搜索查询域名A记录路径"""

    domain = stripdot(domain)

    prefix = f"D{depth} "
    prefix = ''
    logging.debug(f"{prefix} {domain} NS {ns} NSIP {nsip} PATH {path}\n")

    if depth > MAX_DEPTH:
        logging.error(f"{prefix} {domain} 递归深度超过 {MAX_DEPTH}\n")
        new_path = copy.deepcopy(path)
        new_path.append((domain, '$DEPTH$',domain))
        all_paths.append(new_path)
        return

    if len(all_paths) > MAX_PATH_COUNT:
        logging.error(f"{prefix} {domain} 路径数量超过 {MAX_PATH_COUNT}\n")
        return
    
    current_path = path + [(ns, nsip ,domain)]
    current_onpath_domain_ns_list = onpath_domain_ns_list + [(domain, ns)]

    logging.debug(f"{prefix} 当前路径 {current_path}\n")

    # 判断循环依赖
    if len(current_onpath_domain_ns_list) > len(set(current_onpath_domain_ns_list)): # 说明最后一个加入的 queryname,ADNShostname 组合 与之前的重复了。为什么不看IP？其实跟IP没有关系，主要是ADNShostname它自己就无法解析，陷入了循环。我们不应该向同一个NS查询同一个域名两次。

        new_path = copy.deepcopy(current_path)
        new_path.append((domain, '$LOOP$',domain))
        all_paths.append(new_path)

        logging.error(f"{prefix} {domain} 循环依赖 current_onpath_domain_ns_list:{current_onpath_domain_ns_list}")
        # logging.error(f"{prefix} {domain} 循环依赖 current_onpath_domain_ns_list:{current_onpath_domain_ns_list} new_path:{new_path} domain:{domain}")
        logging.info(f"{prefix}current_onpath_domain_ns_list: {current_onpath_domain_ns_list}")

        logging.info(f"{prefix} new_path: {new_path}")
        logging.info(f"{prefix} domain: {domain}\n")
        return        

    # 检查缓存
    output = load_cache(nsip, domain)
    if output:
        logging.debug(f"{prefix}命中缓存\n")
    else:
        # 构造查询命令
        command = f"echo {domain} | zdns A --name-servers={nsip}"
        output, err = run_command(command)
        save_cache(nsip, domain, output)

    # 解析命令输出
    try:
        recv_data = json.loads(output)
    except json.JSONDecodeError:
        # 解析失败，说明没有返回正常回答
        logging.error(f"{prefix} {domain} 解析JSON失败: {output}\n")
        new_path = copy.deepcopy(current_path)
        new_path.append((domain, '$NOJSON$',domain))
        all_paths.append(new_path)
        return
        
    except RecursionError:
        logging.error(f"{prefix} {domain} Maximum recursion depth exceeded\n")
        

    # 判断当前是否下一个访问的就是TLDADNS了。当前访问ROOT的时候这里就需要置为Tru，此时current_path长度为1
    IS_NEXT_TLDADNS = True if len(current_path)==1 else False

    if 'data' in recv_data:
        data = recv_data['data']
        data_status = recv_data['status']
        if data_status != 'NOERROR':
            # 返回状态不正常，结束递归
            logging.debug(f"{prefix} {domain} 返回状态不正常 {ns} {nsip} {data_status}\n")
            new_path = copy.deepcopy(current_path)
            new_path.append((domain, f'$NOIP_{data_status}$',domain))
            all_paths.append(new_path)

        # 检查是否有 "answers" 键
        if 'answers' in data and data['answers']:
            # 找到A记录，结束递归
            answers = list()
            for answer_dict in data['answers']:
                if answer_dict['type'] == 'A':
                    answers.append(answer_dict['answer'])
                elif answer_dict['type'] == 'CNAME':
                    answers.append(stripdot(answer_dict['answer']))

            # 有些时候即使是NOERROR，answer可能什么都没有，join出来 answers_str 为空
            answers_str = ','.join(answers)
            new_path = copy.deepcopy(current_path)
            new_path.append((domain,answers_str,domain))
            all_paths.append(new_path)
            logging.info(f"{prefix} 完成查询\n")            
            return

        # 检查 "additionals" 键
        glue_set = set()
        # glue_vendor_count 用来计数一个vendor被用作几次glue，如果超过2次，就不再进一步递归
        glue_vendor_count = defaultdict(int)
        if 'additionals' in data and data['additionals']:
            
            # 如果下一个要访问的权威不是TLDADNS，那么就可以处理所有的additionals
            if not IS_NEXT_TLDADNS: 
                for additional in data['additionals']:
                    if additional['type'] == 'AAAA': #暂时不处理AAAA记录，但是要加到glue_set中，以免authorities里循环请求
                        next_ns = stripdot(additional['name'])
                        next_ns_sld = extract_sld(next_ns)
                        next_ns_vendor = extract_vendor(next_ns)
                        #glue_vendor_count[next_ns_sld] += 1 # 这里先不限制，因为现在只处理A记录
                        #glue_vendor_count[next_ns_vendor] += 1 # 这里先不限制,因为现在只处理A记录
                        glue_set.add(next_ns)
                    
                    elif additional['type'] == 'A':
                        next_ns = stripdot(additional['name'])
                        next_ns_sld = extract_sld(next_ns)
                        next_ns_vendor = extract_vendor(next_ns)
                        glue_vendor_count[next_ns_sld] += 1
                        glue_vendor_count[next_ns_vendor] += 1
                        glue_set.add(next_ns)
                        if glue_vendor_count[next_ns_vendor] <= MAX_VENDOR_COUNT and glue_vendor_count[next_ns_sld] <= MAX_SLD_COUNT: # 这里还没有加CDN域名限制
                            next_nsip = additional['answer']
                            logging.debug(f"{prefix} 处理additionals {next_ns} {next_nsip}\n")

                            try:
                                dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path, all_paths, current_onpath_domain_ns_list, cache,depth+1)
                            except RecursionError:
                                logging.error(f"{prefix} {domain} Maximum recursion depth exceeded during additionals processing\n")
            
            # 如果下一个要访问的权威是TLDADNS，且只需要跟第一个TLDADNS交互(即 不跟所有TLDADNS进行DFS)
            elif IS_NEXT_TLDADNS and not IF_TLDADNS_DFS:
                for additional in data['additionals']:
                    if additional['type'] == 'AAAA': #暂时不处理AAAA记录，但是要加到glue_set中，以免authorities里循环请求
                        next_ns = stripdot(additional['name'])
                        continue #暂时不处理AAAA记录
                    
                    elif additional['type'] == 'A':
                        next_ns = stripdot(additional['name'])
                        next_nsip = additional['answer']
                        logging.debug(f"{prefix} 处理第一个TLDADNSadditionals {next_ns} {next_nsip}\n")
                        try:
                            dfs_adns_path_alookup(domain, next_ns, next_nsip, current_path, all_paths, current_onpath_domain_ns_list, cache,depth+1)
                            return # 只处理第一个TLDADNS
                        except RecursionError:
                            logging.error(f"{prefix} {domain} Maximum recursion depth exceeded during additionals processing\n")
                        


            # 检查 "authorities" 键
        if 'authorities' in data and data['authorities']:
            have_auth_flag = False
            for authority in data['authorities']:
                if authority['type'] == 'NS':
                    have_auth_flag = True
                    next_ns = stripdot(authority['answer'])
                    if next_ns in glue_set:
                        continue
                    
                    next_ns_sld = extract_sld(next_ns)
                    next_ns_vendor = extract_vendor(next_ns)
                    glue_vendor_count[next_ns_sld] += 1
                    glue_vendor_count[next_ns_vendor] += 1

                    if not (glue_vendor_count[next_ns_vendor] <= MAX_VENDOR_COUNT and glue_vendor_count[next_ns_sld] <= MAX_SLD_COUNT):
                        continue
                    logging.debug(f"{prefix}处理authorities: {next_ns}\n")
                    # 需要查询权威服务器的A记录
                    glueless_query_all_paths = list()
                    try:
                        dfs_adns_path_alookup(next_ns, ROOT, '192.58.128.30', [], glueless_query_all_paths, current_onpath_domain_ns_list, cache,depth+1)
                    except RecursionError:
                        logging.error(f"{prefix} {domain}Maximum recursion depth exceeded during authorities processing\n")
                    for glueless_query_path in glueless_query_all_paths:
                        glueless_next_ns,glueless_next_nsip_answers,_ = glueless_query_path[-1]
                        if glueless_next_nsip_answers.startswith('$') or not glueless_next_nsip_answers:
                            logging.debug(f"{prefix} {domain} authorities向下递归错误")
                            logging.info(f"{prefix} glueless_query_path: {glueless_query_path}")
                            new_path = copy.deepcopy(current_path)
                            new_path.append(glueless_query_path)
                            new_path.append((domain, '$$$',domain)) # 加上终止符号，表示这个路径被前面分支无法解析而提前终止。
                            all_paths.append(new_path)
                            logging.info(f"{prefix} new_path: {new_path}")
                            logging.info(f"{prefix} domain: {domain}\n")
                        else:
                            glueless_next_nsip_list = glueless_next_nsip_answers.split(',')
                            for glueless_next_nsip in glueless_next_nsip_list:
                                new_path = copy.deepcopy(current_path)
                                new_path.append(glueless_query_path)
                                try:
                                    dfs_adns_path_alookup(domain, glueless_next_ns, glueless_next_nsip, new_path, all_paths, current_onpath_domain_ns_list, cache,depth+1)
                                except RecursionError:
                                    logging.error(f"{prefix} {domain}Maximum recursion depth exceeded during authorities processing\n")

                elif authority['type'] == 'SOA' and not have_auth_flag: #只有SOA记录，且没有NS记录
                    logging.debug(f"{prefix}处理authorities SOA: {data}\n")
                    new_path = copy.deepcopy(current_path)
                    new_path.append((domain, '$SOA$',domain))
                    all_paths.append(new_path)      

def thread_func():
    while not q.empty():
        query_domain = q.get_nowait()
        DATETIME = time.strftime("%Y%m%d-%H%M%S", time.localtime())

        ns = ROOT
        nsip = ROOTIP
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

# 测试函数
if __name__ == "__main__":
    

    domain_list = load_data(INPUTPATH)
    # 重新配置日志记录以包含域名
    logging_output_file = f"{LOG_DIR}{suf}_logging.txt"
    logging.basicConfig(filename=logging_output_file, level=LOGGING_LEVEL, format='%(message)s')

    checkpoint_date, checkpoint_inputpath, checkpoint_target = load_checkpoint()
    if checkpoint_date != DATE or checkpoint_inputpath != INPUTPATH:
        # 已经不是今天的查询，检查点无效，清空检查点
        checkpoint_target = None
    print(f"开始查询，检查点: {checkpoint_target}")
    skip = bool(checkpoint_target)
    count = 0
    ###################
    for domain in domain_list:
        if skip:
            if domain == checkpoint_target:
                print(f"找到检查点: {checkpoint_target}，从此处继续...")
                skip = False
            continue
        if domain == extract_sld(domain):
            query_domain = 'www.' + domain
        else:
            query_domain = domain
        q.put(query_domain)
    print(f"[+] 所有数据加载完成")
    ####################


    begin = time.time()
    try:
        threads = []
        for i in range(thread_num):
            threads.append(threading.Thread(target=thread_func))
        for t in threads:
            t.setDaemon(True)  # 守护线程
            t.start()
        for t in threads:
            t.join()  # 等待线程全部完成
        
        print("[+] 所有线程已完成，正在保存...")
    #    except KeyboardInterrupt as err: pass    
    except Exception as e: print('thread error',e,domain)

    end = time.time()
    t = end - begin
    # 转换时分秒格式
    t = time.strftime("%H:%M:%S", time.gmtime(t))
    print('Finish this round: ', len(domain_list), 'domains, using time: ', t)