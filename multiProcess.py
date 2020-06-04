#!/usr/bin/python
# -*- coding:utf-8 -*-

import nmap
import re
import sys
from multiprocessing import Pool
from functools import partial
import time

import pytest
# TODO test several below:
"""
1. --min-para's trade off with effectiveness and accuracy
2. --mtu 60
"""


def nmScan(host, args_):
    nm = nmap.PortScanner()
    tmp = nm.scan(host, arguments=args_, sudo=True)
    #print(f"nmap's command line is {nm.command_line()}")
    """
        result = result + "<h2>ip地址:%s 主机名:[%s]  ......  %s</h2><hr>" %(host,tmp['scan'][host]['hostname'],tmp['scan'][host]['status']['state'])
        try:
            ports = tmp['scan'][host]['tcp'].keys()
            for port in ports:
                info = ''
                if port not in whitelist:
                   info = '<strong><font color=red>Alert:非预期端口</font><strong>&nbsp;&nbsp;'
                else:
                   info = '<strong><font color=green>Info:正常开放端口</font><strong>&nbsp;&nbsp;'
                portinfo = "%s <strong>port</strong> : %s &nbsp;&nbsp;<strong>state</strong> : %s &nbsp;&nbsp;<strong>product<strong/> : %s <br>" %(info,port,tmp['scan'][host]['tcp'][port]['state'],                                                                       tmp['scan'][host]['tcp'][port]['product'])
                result = result + portinfo
        except KeyError,e:
            if whitelist:
                whitestr = ','.join(whitelist)
                result = result + "未扫到开放端口!请检查%s端口对应的服务状态" %whitestr                
            else:
                result = result + "扫描结果正常，无暴漏端口"      
        """
    return tmp["scan"]
    # return tmp.scaninfo()


def getCurTime():
    from datetime import datetime
    time_str = datetime.now().__str__()
    time_str = time_str[-8:].replace(":", "-")
    return time_str


def parseHostList(hostIP):
    """parse host list str into a fixed format of lists

    Arguments:
        hostIP {str} -- str whose format is like "118.229.0-15.0-255"

    Raises:
        ValueError: [can only read in 118.229.0.0/16 or 166.111.0.0/16 ]

    Returns:
        [list] -- [list of host list]

    Examples:
        >>> parseHostList("118.229.0-15.0-255")[1]
        '118.229.1.0/24'
        >>> parseHostList("118.229.0-15.0-255")[15]
        '118.229.15.0/24'
        >>> parseHostList("166.111.0.0/16")[255]
        '166.111.255.0/24'
    """
    if(hostIP == "118.229.0-15.0-255"):  # parse into 15 tasks
        return [f"118.229.{x}.0/24" for x in range(16)]

    elif(hostIP == "166.111.0.0/16"):  # parse into 256 tasks
        return [f"166.111.{x}.0/24" for x in range(256)]

    else:
        raise ValueError("hostlist not right")


def parseHostListToSingle(hostIP):
    """parse host list str into a fixed format of ip address lists , in which each address refers to a single host

    Arguments:
        hostIP {str} -- str whose format is like "118.229.0-15.0/24"

    Returns:
        [list] -- [list of host list]

    Examples:
        >>> parseHostListToSingle("118.229.0-15.0/24")[1]
        '118.229.0.1'
        >>> parseHostListToSingle("118.229.0-15.0/24")[15]
        '118.229.0.15'
        >>> parseHostListToSingle("166.111.0.0/16")[256]
        '166.111.1.0'
    """
    address, maskLen = hostIP.split("/")   # 118.229.0-15.0 , 24
    ipAddress = []
    if(maskLen == "24"):
        start_, end_ = address.split("-")  # 118.229.0 , 15.0
        start = start_.split(".")[-1]   # 118.229.0 --> 0
        end = end_.split(".")[0]        # 15.0 --> 15
        for i in range(int(start), int(end)+1):
            for j in range(0, 256):
                seq = address.split(".")[0:2]
                seq.extend([str(i), str(j)])
                ipAddress.append(".".join(seq))
    elif(maskLen == "16"):
        for i in range(0, 256):
            for j in range(0, 256):
                seq = address.split(".")[0:2]
                seq.extend([str(i), str(j)])
                ipAddress.append(".".join(seq))
    else:
        raise ValueError("mask length neither 16 nor 24")
    return ipAddress


if __name__ == "__main__":
    startTime = time.time()
    curTime = getCurTime()
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str,
                        default="118.229.0-15.0/24")  # 118.229.14.0/24
    # not using sA which will report error
    parser.add_argument(
        # '--ags', type=str, default="--script=snmp-interfaces --min-parallelism 100 -sV -T4 -O -n -PE -PA -f")
        '--ags', type=str, default="--script=snmp-interfaces -sV -T4 -O -n -PE -PA -PS -PU53,161 --mtu 64 -f")     # version 2 of Linbo Hui
    parser.add_argument('--fileName', type=str, default=curTime)
    args = parser.parse_args()

    hostlist = parseHostListToSingle(args.host)
    ags = args.ags  # "-sV -T4 -O -v -n -PE -PA -f "
    processNum = 100
    pool = Pool(processNum)
    nmargu = partial(nmScan, args_=ags)
    results = []

    for host in hostlist:
        results.append(pool.apply_async(nmargu, (host,)))

    pool.close()
    pool.join()

    endTime = time.time()
    print(f"cost time {endTime-startTime}")

    fileName = args.host+args.fileName
    fileName = "../data/"+fileName.split("/")[0]
    with open("../data/"+fileName, "a") as ff:
        for res in results:
            print(res.get(), file=ff)
            #print(res.get())
        print(f"\n\ncost time {endTime-startTime}", file=ff)

"""ip address range list
166.111.0.0/16
118.229.0-15.0/24
101.6.0.0/16
101.5.0.0/16
183.172.0.0/16
59.66.0-63.0/24
183.173.0-127.0/24
"""

# 这几个都不work啊...
# sudo nmap -sU -p 161 -T4 -n -Pn -d -v 118.229.14.0/24
# sudo nmap -sU --script nbstat -p 137 118.229.14.0/24
# sudo nmap -sU -p 161 --script=snmp-interfaces 118.229.14.0/24
# sudo nmap -sU -p 161 -S 118.229.14.21 -e eth1 --script=snmp-interfaces 118.229.14.0/24
