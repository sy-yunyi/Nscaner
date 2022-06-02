import subprocess
import os
import time
import random
from multiprocessing import Pool
import json
import pdb
from tqdm import tqdm
import argparse
from hashlib import md5

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


def scanning_domain_zmap(domain,shost,myinterface=None):
    # echo 'toortoor' | sudo -S 
    if myinterface:
        cmd = f"zmap -p 53 -B 3M --probe-module=dns --probe-args='A,{domain}' -O json --output-fields=* --interface={myinterface} --output-file=./data/zmap/{domain}-.res --list-of-ips-file={shost}"
    else:
        cmd = f"zmap -p 53 -B 3M --probe-module=dns --probe-args='A,{domain}' -O json --output-fields=* --output-file=./data/zmap/{domain}-.res --list-of-ips-file={shost}"
    p = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    print(p.stdout.readlines())
    return domain

def zmap_results_out(detectver):
    file_root_path = "./data/zmap"
    file_outroot_path = "./data/zmap_res"
    file_tarroot_path = "./data/zmap_tar"
    file_list = os.listdir(file_root_path)

    if not os.path.exists(file_outroot_path):
        os.makedirs(file_outroot_path)
    if not os.path.exists(file_tarroot_path):
        os.makedirs(file_tarroot_path)
    if not os.path.exists(file_root_path):
        os.makedirs(file_root_path)

    for fi in file_list:
        in_file = open(os.path.join(file_root_path,fi),"r")
        out_file = open(os.path.join(file_outroot_path,fi),"w")
        out_to_file(in_file,out_file,detectver)
        os.system(f"tar -zcvf {os.path.join(file_tarroot_path,fi)}.tar.gz {os.path.join(file_root_path,fi)}")
        os.system(f"rm -f {os.path.join(file_root_path,fi)}")
    
    os.system(f"tar -zcvf ./data/zmap_res_all-{detectver}.tar.gz {file_outroot_path}")
    os.system(f"tar -zcvf ./data/zmap_data_res_all-{detectver}.tar.gz {file_tarroot_path}")
    





def out_to_file(in_file,out_file,detectver):
    for line in in_file:
        lj = json.loads(line)
        timestamp = lj['timestamp_str']
        detectversion = detectver
        saddr = lj['saddr']
        saddr_int = lj['saddr_raw']
        ipid = lj['ipid']
        ttl = lj['ttl']
        dport = lj['dport']
        udp_len = lj['udp_len']
        dns_id = lj['dns_id']
        dns_rd = lj['dns_rd']
        dns_tc = lj['dns_tc']
        dns_aa = lj['dns_aa']
        dns_opcode = lj['dns_opcode']
        dns_qr = lj['dns_qr']
        dns_rcode = lj['dns_rcode']
        dns_cd = lj['dns_cd']
        dns_ad = lj['dns_ad']
        dns_z = lj['dns_z']
        dns_ra = lj['dns_ra']
        dns_qdcount = lj['dns_qdcount']
        dns_ancount = lj['dns_ancount']
        dns_nscount = lj['dns_nscount']
        dns_arcount = lj['dns_arcount']
        smd5 = md5(line.encode()).hexdigest()
        dns_parse_err = lj['dns_parse_err']
        dns_unconsumed_bytes = lj["dns_unconsumed_bytes"]

        answer0_name = ""
        answer0_type = -1
        answer0_type_str = ""
        answer0_class = -1
        answer0_ttl = -1
        answer0_rdlength = -1
        answer0_rdata = ""
        answer0_rdata_ip = -1
        answer0_rdata_timestamp = ""
        answer0_rdata_port = -1
        answers_data = ""
        question0_name = ""
        question0_type = -1
        question0_type_str = ""
        question0_class = -1
        questions_data = ""
        authority0_name = ""
        authority0_type = -1
        authority0_type_str = ""
        authority0_class = -1
        authority0_ttl = -1
        authority0_rdlength = -1
        authority0_rdata = ""
        authorities_data = ""
        additional0_name = ""
        additional0_type = -1
        additional0_type_str = ""
        additional0_class = -1
        additional0_rdlength = -1
        additional0_ttl = -1
        additional0_rdata = ""
        additionals_data = ""

        ans = {}
        i = 0
        for ai in lj['dns_answers']:
            if 'rdata' in ai.keys():
                ans[i]=ai
                if i == 0:
                    answer0_name = ai['name']
                    answer0_type = ai['type']
                    answer0_type_str = ai['type_str']
                    answer0_class = ai['class']
                    answer0_ttl = ai['ttl']
                    answer0_rdlength = ai['rdlength']
                    answer0_rdata = ai['rdata']
                    answer0_rdata_ip = ""
                    answer0_rdata_timestamp = ""
                    answer0_rdata_port = -1
                    i += 1

        answers_data = json.dumps(ans)

        aqs = {}
        i = 0
        for ai in lj['dns_questions']:
            aqs[i] = ai
            if i==0:
                question0_name = ai['name']
                question0_type = ai['qtype']
                question0_type_str = ai['qtype_str']
                question0_class = ai['qclass']
                i += 1
        questions_data = json.dumps(aqs) 

        aus = {}
        i = 0 
        for ai in lj['dns_authorities']:
            if 'rdata' in ai.keys():
                aus[i] = ai
                if i==0:
                    authority0_name = ai['name']
                    authority0_type = ai['type']
                    authority0_type_str = ai['type_str']
                    authority0_class = ai['class']
                    authority0_ttl = ai['ttl']
                    authority0_rdlength = ai['rdlength']
                    authority0_rdata = ai['rdata']
                    i += 1

        authorities_data = json.dumps(aus)

        ads = {}
        i = 0 
        for ai in lj['dns_additionals']:
            if 'rdata' in ai.keys():
                ads[i]=ai
                if i==0:
                    additional0_name = ai['name']
                    additional0_type = ai['type']
                    additional0_type_str = ai['type_str']
                    additional0_class = ai['class']
                    additional0_rdlength = ai['rdlength']
                    additional0_ttl = ai['ttl']
                    additional0_rdata = ai['rdata']
                    i += 1

        additionals_data = json.dumps(ads)


        
        out_file.write(f"{timestamp},{detectversion},{saddr},{saddr_int},{ipid},{ttl},{dport},{udp_len},{dns_id},{dns_rd},{dns_tc},{dns_aa},{dns_opcode},{dns_qr},{dns_rcode},{dns_cd},{dns_ad},{dns_z},{dns_ra},{dns_qdcount},{dns_ancount},{dns_nscount},{dns_arcount},{answer0_name},{answer0_type},{answer0_type_str},{answer0_class},{answer0_ttl},{answer0_rdlength},{answer0_rdata},{answer0_rdata_ip},{answer0_rdata_timestamp},{answer0_rdata_port},{answers_data},{question0_name},{question0_type},{question0_type_str},{question0_class},{questions_data},{authority0_name},{authority0_type},{authority0_type_str},{authority0_class},{authority0_ttl},{authority0_rdlength},{authority0_rdata},{authorities_data},{additional0_name},{additional0_type},{additional0_type_str},{additional0_class},{additional0_rdlength},{additional0_ttl},{additional0_rdata},{additionals_data},{dns_unconsumed_bytes},{dns_parse_err},{smd5}"+"\n")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument("-dv",help="detection version",default=1)
    parser.add_argument("-psize",help="pool size",default=3,type=int)
    parser.add_argument("-td",help="target domain",default="./data/gfw.list")
    parser.add_argument("-ips",help="host ips",default="./data/name_server_ips.txt")
    parser.add_argument("-iface",help="interface",default="0")
    # parser.add_argument("-s")
    # parser.add_argument("-tf")

    myargs = parser.parse_args()
    # # ipv42base(file_target=args.t,file_size=args.s)
    
    # p=Pool(3) #进程池中从无到有创建三个进程,以后一直是这三个进程在执行任务
    p=Pool(myargs.psize) #进程池中从无到有创建三个进程,以后一直是这三个进程在执行任务

    print("zmap scanning ...")
    fp = open(myargs.td,"r")
    lines = fp.readlines()
    lines = [line.strip() for line in lines]

    for ni in tqdm(lines):
        if myargs.iface != "0":
            p.apply_async(scanning_domain_zmap,args=(ni,myargs.ips,myargs.iface)) # 异步运行，根据进程池中有的进程数，每次最多3个子进程在异步执行
        else:
            p.apply_async(scanning_domain_zmap,args=(ni,myargs.ips))

    p.close()
    p.join()
    zmap_results_out(myargs.dv)




    







