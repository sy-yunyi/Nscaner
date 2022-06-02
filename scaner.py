import subprocess
import os
import time
import random
from multiprocessing import Pool
import json
import pdb
from tqdm import tqdm


def scanning_domain(ns):
    cmd = f"cat /home/usertoor/silex/domain_mirroring/data/domains_100.txt | /home/usertoor/silex/zdns/zdns/zdns A -name-servers {ns}"
    # cmd = f"cat /home/usertoor/silex/ghostR/data/zonefile_ns_records_domain_0531_uniq.txt | /home/usertoor/silex/zdns/zdns/zdns A -name-servers {ns}"
    # cmd = f"cat 'baidu.com' | /home/usertoor/silex/zdns/zdns/zdns A -name-servers {ns}"
    p = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    results = []
    for line in p.stdout.readlines():
        lj = json.loads(line)
        dstatus = lj['status']
        dname = lj['name']
        if "answers" in lj['data'].keys():
            for ai in lj['data']['answers']:
                aip = ai['answer']
                atype = ai['type']
                aname = ai['name']
                results.append([dname,dstatus,aip,aname,atype,ns])
        else:
            results.append([dname,dstatus,"","","",ns])

    return results


def scanning_domain_zmap(domain):
    # cmd = f"cat /home/usertoor/silex/domain_mirroring/data/domains_100.txt | /home/usertoor/silex/zdns/zdns/zdns A -name-servers {ns}"
    # cmd = f"cat /home/usertoor/silex/ghostR/data/zonefile_ns_records_domain_0531_uniq.txt | /home/usertoor/silex/zdns/zdns/zdns A -name-servers {ns}"
    # cmd = f"cat 'baidu.com' | /home/usertoor/silex/zdns/zdns/zdns A -name-servers {ns}"
    cmd = f"zmap -p 53 -B 3M --probe-module=dns --probe-args='A,{domain}' -O json --output-fields=* --output-file=./data/zmap/{domain}-.res --list-of-ips-file=./data/name_server_ips.txt"
    p = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    # --interface=enp96s0f1
    print(p.stdout.readlines())
    results = []
    # for line in p.stdout.readlines():
    #     lj = json.loads(line)
    #     dstatus = lj['status']
    #     dname = lj['name']
    #     if "answers" in lj['data'].keys():
    #         for ai in lj['data']['answers']:
    #             aip = ai['answer']
    #             atype = ai['type']
    #             aname = ai['name']
    #             results.append([dname,dstatus,aip,aname,atype,ns])
    #     else:
    #         results.append([dname,dstatus,"","","",ns])

    return results


if __name__ == '__main__':
    p=Pool(3) #进程池中从无到有创建三个进程,以后一直是这三个进程在执行任务
    res_l=[]
    # fp = open("/home/usertoor/silex/domain_mirroring/data/fdnsnew.txt","r")
    # print("scanning fdns...")
    # fp = open("/home/usertoor/silex/domain_mirroring/data/fdnsnew.txt","r")
    # lines = fp.readlines()
    # lines = [line.strip() for line in lines]


    # 获取NS IP，验证其是否会响应解析----
    # print("scanning ns domain 100...")
    # fp = open("/home/usertoor/silex/domain_mirroring/data/name_server_ips.txt","r")
    # lines = fp.readlines()
    # lines = [line.strip() for line in lines]

    # print("scanning ns valid ...")
    # lines = ["8.8.8.8"]

    # 使用zmap扫描
    print("zmap scanning ...")
    fp = open("./data/gfw.list","r")
    lines = fp.readlines()
    lines = [line.strip() for line in lines]
    # lines = ["baidu.com"]
    for ni in tqdm(lines):
        # res=p.apply_async(scanning_domain,args=(ni,)) # 异步运行，根据进程池中有的进程数，每次最多3个子进程在异步执行
        p.apply_async(scanning_domain_zmap,args=(ni,)) # 异步运行，根据进程池中有的进程数，每次最多3个子进程在异步执行
#                                           # 返回结果之后，将结果放入列表，归还进程，之后再执行新的任务
#                                           # 需要注意的是，进程池中的三个进程不会同时开启或者同时结束
#                                           # 而是执行完一个就释放一个进程，这个进程就去接收新的任务。  
        # res_l.append(res)
    # print("done ... ")

#     # 异步apply_async用法：如果使用异步提交的任务，主进程需要使用jion，等待进程池内任务都处理完，然后可以用get收集结果
#     # 否则，主进程结束，进程池可能还没来得及执行，也就跟着一起结束了
    p.close()
    p.join()
    # print("saving ... ")
    # fo = open("/home/usertoor/silex/domain_mirroring/data/scanning_name_server_response.res","w")
    # for res in res_l:
    #     for ri in res.get():
    #         fo.write(",".join(ri)+"\n")







# p = subprocess.Popen("cat /home/usertoor/silex/domain_mirroring/data/domains.txt | /home/usertoor/silex/zdns/zdns/zdns A -name-servers 85.159.233.158",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
# p = subprocess.Popen("sudo zmap -p 53 85.159.233.158/24 --probe-module=dns --probe-args='A,sixpence.group' --output-fields=*  --interface=enp96s0f1",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
# p.stdin.write("toortoor".encode())

# for line in p.stdout.readlines():
#     print(line)


# file_path = "/home/data1/public-dataset/czds_zonefile/file_1091/rio_2022_05_25_03_16.txt"
# with open(file_path,"r") as fp:
#     # flines = fp.readlines()
#     for line in fp:
#         try:
#             if not line.startswith(";") and (line.split("\t")[3] == "ns"):
#                 pass
#                 # lines.append(file.split("_")[0]+","+line.split("\t")[0]+","+line.split("\t")[4])
#                 # fpo.write(file.split("_")[0]+","+line.split("\t")[0]+","+line.split("\t")[4])
#         except:
#             print(line)

# scanning_domain("8.8.8.8")