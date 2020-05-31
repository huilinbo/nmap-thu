#!/usr/bin/python
# -*- coding:utf-8 -*-

import nmap
import argparse
import time
import os
import sys
from multiprocessing import Pool
from functools import partial


def nm_scan(host, args):
    nm = nmap.PortScanner()
    result = nm.scan(host, arguments=args, sudo=True)
    # print("nmap's command line is", nm.command_line())
    return result['scan']

def parse_hosts(ip_space):
    digits = ip_space.split('.')
    d3 = digits[2].split('-')
    d4 = digits[3].split('-')
    hosts = []
    for i in range(int(d3[0]), int(d3[1])+1):
        for j in range(int(d4[0]), int(d4[1])+1):
            host = digits[0] + '.' + digits[1] + '.' + str(i) + '.' + str(j)
            hosts.append(host)
    return hosts


if __name__ == "__main__":
    result_dir = './nmap_results'
    if not os.path.exists(result_dir):
        os.mkdir(result_dir)
    parser = argparse.ArgumentParser()
    parser.add_argument('--args', type=str, default="--script=snmp-interfaces -sV -T4 -O -R -PE -PA -PS -PU53,161 --mtu 64 -f")
    # -sV Version Detection
    # -T4 Timing template, T4 is aggressive
    # -O Operating system detection
    # -R RDNS
    # -n No DNS
    # -v Verbosity level
    # -f Fragment IP packets
    # -PE ICMP ping
    # -PA ACK ping
    # -PS SYN ping
    # -PU UDP probes
    # --mtu 16
    args = parser.parse_args().args
    # ip_spaces = ['59.66.0-255.0-255']
    # ip_spaces = ['166.111.0-255.0-255']
    # ip_spaces = ['118.229.0-31.0-255']
    # ip_spaces = ['183.172.0-255.0-255']
    # ip_spaces = ['183.173.0-255.0-255']
    # ip_spaces = ['101.5.0-255.0-255']
    ip_spaces = ['101.6.0-255.0-255']
    for ip_space in ip_spaces:
        print(ip_space)
        start_time = time.time()
        hosts = parse_hosts(ip_space)
        results = []
        nmarg = partial(nm_scan, args=args)
        process_num = 100       # trade off with effectiveness and accuracy
        pool = Pool(process_num)        
        for host in hosts:
            results.append(pool.apply_async(nmarg, (host,)))
        pool.close()
        pool.join()
        end_time = time.time()
        time_used = round((end_time-start_time)/60, 2)
        with open(result_dir+'/'+ip_space, 'w') as f:
            cnt = 0
            for result in results:
                res = str(result.get())
                cnt += res.count('ipv4')        # each 'ipv4' corresponds to an up host
                f.write(res+'\n')
            conclusion ='Scanning ' + ip_space + ' used ' + str(time_used) + ' minutes. ' + str(cnt) + '/' + str(len(results)) + ' hosts up.'
            f.write('\n' + conclusion + '\n')
            print(conclusion)
