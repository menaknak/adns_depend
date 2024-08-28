import subprocess
import json
import time
import tldextract
import threading
import os
import time
import queue
import threading
import json
from threading import Lock

print('Version: 240730 v1') 

INPUTFILE='./input/test_1_sld.txt'
INPUTFILE='./input/baidu.txt'

DATETIME = time.strftime('%Y%m%d-%H-%M',time.localtime())

timeout_value = '15'
TIMEOUT = '--timeout '+timeout_value

thread_num = 64

OUTPUTPATH = './output'
os.makedirs(f"{OUTPUTPATH}", exist_ok=True)

suf = INPUTFILE.split('/')[-1].split('.')[0]
LOGNAME=f'{suf}-{timeout_value}timeout-{DATETIME}.log'

# LOGNAME=f'{DATETIME}.log'

ERRORLOG=f"{OUTPUTPATH}/error/{LOGNAME}"
os.makedirs(f"{OUTPUTPATH}/error", exist_ok=True)


def get_v6_address():
    result = os.popen("ip addr show | sed -n -e 's/^.*inet6 \\([^ ]*\\)\\/.* scope global.*$/\\1/p'").read()
    ip_list = [line.strip() for line in result.splitlines() if line.strip()]
    ip = ip_list[0] if ip_list else None
    return ip
IPV6 = get_v6_address()







q = queue.Queue() # 工作队列，用于线程资源调度
mutex1 = Lock()
mutex2 = Lock()

def extract(rev_a):
    if 'answers' in rev_a['data']:
        res = {
                    'answers_a': [answer['answer'] for answer in rev_a['data']['answers']],
                    'name': rev_a['name'],
                    'status': rev_a['status'],
                    'timestamp': rev_a['timestamp'],
                    'resolver': rev_a['data']["resolver"]
                }
    else:
        res = {
            'answers_adata': rev_a['data'],
            'name': rev_a['name'],
            'status': rev_a['status'],
            'timestamp': rev_a['timestamp']
        }
    return res


def extract_sld(fqdn):
    result = tldextract.extract(fqdn)
    sld = f"{result.domain}.{result.suffix}"
    return sld


def run_zdns_cmd(cmd):
    retry_count = 1
    max_retries = 5
    
    while retry_count < max_retries:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        output_decoded = output.decode('utf-8')
        if 'TIMEOUT' not in output_decoded:
            break
        retry_count += 1
        time.sleep(5)
    return output_decoded, error.decode('utf-8')

# def run_command_with_retry(command, max_retries=5):
#     """运行系统命令并返回结果，带有重试机制"""
#     retry_count = 1
#     while retry_count <= max_retries:
#         result = subprocess.run(command, shell=True, capture_output=True, text=True)
#         if 'TIMEOUT' not in result.stdout:
#             break
#         retry_count += 1
#         time.sleep(5)
#     return result.stdout, result.stderr


def load_data(filename):
    ip_list=[]
    with open(filename,'r') as f:
        ip_list=f.readlines()
    return [i.strip() for i in ip_list]

def thread_func(DATETIME):
    while not q.empty():
        domain = q.get_nowait()
        # 调用 extract_sld.py 提取 SLD
        sld = extract_sld(domain)

        # 调用 zdns NS 查询
        if sld.endswith('edu.cn'):
            parentzonecmd = f'echo "{sld}" | zdns NS --iterative {TIMEOUT} --max-depth=3'
        else:
            parentzonecmd = f'echo "{sld}" | zdns NS --iterative {TIMEOUT} --max-depth=2'
        rev_raw, err = run_zdns_cmd(parentzonecmd)
        temp = {}
        if 'answers' in rev_raw:
            rev = json.loads(rev_raw.strip())
            # 提取需要的字段并重命名为 temp
            temp = {
                'answers_ns': [answer['answer'] for answer in rev['data']['answers']],
                'name': rev['name'],
                'status': rev['status'],
                'timestamp': rev['timestamp'],
                # "resolver": rev['data']['resolver']
            }

        

            # 遍历 answers_ns 中的每个 answer
            for hostname in temp['answers_ns']:
                # 执行 zdns A 查询
                rev_a,err0 = run_zdns_cmd(f'echo "{hostname}" | zdns A --iterative {TIMEOUT}')
                if 'answers' in rev_a:
                    rev_a = json.loads(rev_a.strip())
                    # 提取 answers_nsa 字段并追加到 temp
                    answers_a = [(hostname,answer['answer']) for answer in rev_a['data']['answers']]
                    temp['answers_nsa'] = temp.get('answers_nsa', []) + answers_a

                    #加一致性验证 for _,nsip in temp['answers_nsa']:  echo "{sld}" | zdns NS --name-servers={nsip} {TIMEOUT}
                    nsipset = set([e[1] for e in temp['answers_nsa']])
                    childzone_data = []
                    for nsip in nsipset:
                        
                        # 调用 zdns NS 查询
                        rev_c, err = run_zdns_cmd(f'echo "{sld}" | zdns NS --name-servers={nsip} --iterative {TIMEOUT}')
                        if 'data' in rev_c:
                            rev_c = json.loads(rev_c.strip())
                            childzone_json={
                                'data': rev_c['data'],
                                'status': rev_c['status']
                            }
                        else:
                            rev_c = json.loads(rev_c.strip())
                            childzone_json = {
                                #'data': 'No child zone', # 'No child zone on this server'
                                'status': rev_c['status']
                            }    



                        # 调用 zdns A 查询
                        rev_c, err = run_zdns_cmd(f'echo "www.{sld}" | zdns A --name-servers={nsip} --iterative {TIMEOUT}')
                        if 'data' in rev_c:
                            rev_c = json.loads(rev_c.strip())
                            childzone_json_a={
                                'data': rev_c['data'],
                                'status': rev_c['status']
                            }
                        else:
                            rev_c = json.loads(rev_c.strip())
                            childzone_json_a = {
                                #'data': 'No child zone', # 'No child zone on this server'
                                'status': rev_c['status']
                            }    
                        childzone_data.append([nsip,childzone_json,childzone_json_a])

                        

                    temp['answers_nsa_childzone']=childzone_data

                # 执行 zdns AAAA 查询
                rev_4a,err1 = run_zdns_cmd(f'echo "{hostname}" | zdns AAAA --iterative {TIMEOUT}')
                try:
                    if 'answers' in rev_4a:
                        rev_4a = json.loads(rev_4a.strip())

                        # 提取 answers_ns4a 字段并追加到 temp
                        answers_4a = [(hostname,answer['answer']) for answer in rev_4a['data']['answers']]
                        temp['answers_ns4a'] = temp.get('answers_ns4a', []) + answers_4a

                        #加一致性验证 for _,nsip in temp['answers_nsa']:  echo "{sld}" | zdns NS --name-servers={nsip} {TIMEOUT}
                        nsipset = set([e[1] for e in temp['answers_ns4a']])
                        childzone_data = []
                        for nsip in nsipset:
                            # 调用 zdns NS 查询
                            rec_c, err = run_zdns_cmd(f'echo "{sld}" | zdns NS --local-addr={IPV6} --name-servers=[{nsip}] --iterative {TIMEOUT}')
                            if 'data' in rec_c:
                                rec_c = json.loads(rec_c.strip())
                                childzone_json={
                                    'data': rec_c['data'],
                                    'status': rec_c['status']
                                }
                            else:
                                rec_c = json.loads(rec_c.strip())
                                childzone_json = {
                                    #'data': 'No child zone', # 'No child zone on this server'
                                    'status': rec_c['status']
                                }    


                            # 调用 zdns A 查询
                            rev_c, err = run_zdns_cmd(f'echo "www.{sld}" | zdns A --local-addr={IPV6} --name-servers=[{nsip}] --iterative {TIMEOUT}')
                            if 'data' in rev_c:
                                rev_c = json.loads(rev_c.strip())
                                childzone_json_a={
                                    'data': rev_c['data'],
                                    'status': rev_c['status']
                                }
                            else:
                                rev_c = json.loads(rev_c.strip())
                                childzone_json_a = {
                                    #'data': 'No child zone', # 'No child zone on this server'
                                    'status': rev_c['status']
                                }    
                            childzone_data.append([nsip,childzone_json,childzone_json_a])
                        
                        temp['answers_ns4a_childzone']=childzone_data

                except Exception as e:
                    with open(ERRORLOG, 'a') as log_file:
                        log_file.write(f"exception: {repr(e)}\nrec_c: {rec_c}\nerr: {err}\ntemp: {temp}\n$$$\n")       



        
        else:
            rev = json.loads(rev_raw.strip())
            temp = {
                'data': rev['data'],
                'name': rev['name'],
                'status': rev['status'],
                'timestamp': rev['timestamp']
            } 

        if 'additionals' in rev_raw:
            rev = json.loads(rev_raw.strip())
            l = []
            for answer in rev['data']['additionals']:
                if 'answer' in answer:
                    l.append((answer['name'],answer['answer'],answer['type']))
            # 提取需要的字段并重命名为 temp
            temp['additionals'] = l

        if 'authorities' in rev_raw:
            rev = json.loads(rev_raw.strip())
            # 提取需要的字段并重命名为 temp
            l1 = []
            for answer in rev['data']['authorities']:
                if 'answer' in answer:
                    l.append((answer['name'],answer['answer'],answer['type']))
            # 提取需要的字段并重命名为 temp
            temp['authorities'] = l1


        
        mutex1.acquire()
        # 将 temp 追加到 LOGNS 文件中
        with open(f'{OUTPUTPATH}/ADNS/{LOGNAME}', 'a') as log_file:
            log_file.write(json.dumps(temp) + '\n')
        mutex1.release()

    
    return


domain_list = load_data(INPUTFILE)


###################
for domain in domain_list:
    q.put(domain)
print(f"[+] 所有数据加载完成")
####################


begin = time.time()
# LOG['start_time']=time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime())
try:
    threads = []
    for i in range(thread_num):
        threads.append(threading.Thread(target=thread_func,args=(DATETIME,)))
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



# python3 /home/script/scheduler.py