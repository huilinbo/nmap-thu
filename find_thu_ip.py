#!/usr/bin/python
#-*- coding:utf-8 -*-

# Tsinghua has 6B ip addresses.
# This script use whois to filter the address space belongs to Tsinghua.
# Simply run the script and thu ips will be stored in ./ip_thu/
# There may output some errors, I choose to ignore them.

import os
import time
import csv
from multiprocessing.dummy import Pool

result_dir = 'ip_about_thu'     # stored all ips about thu
final_results = 'ip_thu'        # only stored thu ips
if not os.path.exists(result_dir):
    os.mkdir(result_dir)
if not os.path.exists(final_results):
    os.mkdir(final_results)

def check_one_ip(ip):
    cmd = 'whois ' + ip
    # print('Checking ' + ip)
    try:
        results = os.popen(cmd).read()
        if 'tsinghua' in results.lower():
            with open(result_dir + '/' + ip, 'w') as f:
                f.write(results)
                f.close()
    except:
        pass

def check_result():
    ip_lists = os.listdir(result_dir)
    with open(final_results + '/ip_results.csv', 'w') as csv_file:
        fieldnames = ['inetnum', 'netname', 'descr']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for ip in ip_lists:
            with open(result_dir + '/' + ip, 'r') as f:
                inetnum = ''
                netame = ''
                descr = ''
                for line in f.readlines():
                    if line.startswith('inetnum'):
                        inetnum = line[16:-1]
                    elif line.startswith('netname'):
                        netame = line[16:-1]
                    elif line.startswith('descr'):
                        descr += line[15:-1]
                if netame == 'TSINGHUA-CN' or netame == 'TUNET':    # That means IP is registered with THU
                    cmd = 'cp ' + result_dir + '/' + ip + ' ' + final_results + '/'
                    os.system(cmd)
                    writer.writerow({'inetnum': inetnum, 'netname': netame, 'descr': descr})
                f.close()
        csv_file.close()

def main():
    args = []
    for a in range(0, 256):
        for b in range(0, 256):
            this_ip = str(a) + '.' + str(b) + '.0.0'
            args.append((this_ip))

    pool = Pool(1000)       # opened 1000 parallel processes, should be reconsidered under different servers.
    pool.map(check_one_ip, args)
    pool.close()
    pool.join()


if __name__ == "__main__":
    start_time = time.time()
    main()
    check_result()
    end_time = time.time()
    print('Consumed ' + str(round((end_time - start_time)/60, 2)) + ' minutes.')      # 90 min under 1000 parallel
