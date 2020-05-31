#!/usr/bin/python
#-*- coding:utf-8 -*-

# This script convert python-nmap json results to MySQL database.
# First you need to check MySQL host, user and passwd is correct and make sure it works.

import pymysql
import json
import os
import re
import sys


def get_ip_lists(ip_space):
    ip_lists = []
    digits = ip_space.split('.')
    d3 = digits[2].split('-')
    d4 = digits[3].split('-')
    for i in range(int(d3[0]), int(d3[1])+1):
        for j in range(int(d4[0]), int(d4[1])+1):
            this_ip = digits[0]+'.'+digits[1]+'.'+str(i)+'.'+str(j)
            ip_lists.append(this_ip)
    return ip_lists


def purge(string):
    result = string.replace('{', '')
    result = result.replace('}', '')
    result = result.replace('\'', '')
    return result


def re_sub_1(matched):
    val = matched.group('val')
    return ', \"' + val[2:-2] + '\": '


def re_sub_2(matched):
    val = matched.group('val')
    return '{\"' + val[1:-2] + '\": '


def pre_process(string):
    result = string.replace('None', '\'None\'')
    result = result.replace('\"', '`')
    result = result.replace('\'', '\"')
    result = result.replace('`Micro-Star INT"L`', '\"Micro-Star INTL\"')    # a very special case
    result = re.sub('(?P<val>, \d+: )', re_sub_1, result)
    result = re.sub('(?P<val>\{\d+: )', re_sub_2, result)
    return result


def creat_table(cursor, db_name, table_name, table_head):
    cursor.execute('DROP DATABASE IF EXISTS ' + db_name)
    cursor.execute('CREATE DATABASE ' + db_name)
    cursor.execute('USE ' + db_name)
    cursor.execute('DROP TABLE IF EXISTS ' + table_name)
    statement = 'CREATE TABLE IF NOT EXISTS ' + table_name + ' ' + table_head
    cursor.execute(statement)
    print('Successfully created table ' + table_name + '!\n')


def init_table(db, cursor, table_name, IP_spaces):
    print('Initing table ' + table_name + ' ......\n')
    for ip_space in IP_spaces:
        ip_lists = get_ip_lists(ip_space)
        for ip in ip_lists:
            statement = 'INSERT INTO ' + table_name + ' (IPv4) VALUES (\''  + ip + '\');'
            cursor.execute(statement)
        db.commit()
    print('Init table ' + table_name + ' completed!\n')


def read_json(json_dir, json_file):
    print('Reading data from ' + json_file +' ......\n')
    records = []
    with open(json_dir + json_file, 'r') as f:
        while True:
            line = pre_process(f.readline())
            if line.startswith('{\"'):
                try:
                    hosts = json.loads(line)
                except:
                    print(line)
                    sys.exit(0)
                for host in hosts:
                    record = {}
                    host_data = hosts[host]
                    record['HOSTNAME'] = host_data['hostnames'][0]['name']
                    record['IPv4'] = host_data['addresses']['ipv4']
                    record['STATUS'] = host_data['status']['state']
                    try:
                        record['OSNAME'] = purge(str(host_data['osmatch'][0]['name']))
                        record['ACCURACY'] = purge(str(host_data['osmatch'][0]['accuracy']))
                        osclass = host_data['osmatch'][0]['osclass'][0]
                        record['DTYPE'] = osclass['type']
                        record['VENDOR'] = osclass['vendor']
                        record['CPE'] = purge(str(osclass['cpe']))
                    except:
                        record['OSNAME'] = ''
                        record['ACCURACY'] = 'NULL'
                        record['OSCLASS'] = ''
                        record['DTYPE'] = ''
                        record['VENDOR'] = ''
                        record['CPE'] = ''
                    record['PORTUSED'] = purge(str(host_data['portused']))
                    try:
                        record['UPTIME'] = round(float(host_data['uptime']['seconds'])/(24*60*60), 2)
                    except:
                        record['UPTIME'] = 'NULL'
                    records.append(record)           
            elif line.startswith('{'):
                continue
            else:
                break
    print('Read data from ' + json_file + ' completed!\n')
    return records


def update(db, cursor, table_name, records):
    print('Updating records ......\n')
    for record in records:
        statement = 'UPDATE ' + table_name + ' SET ' + \
                    'HOSTNAME=\'' + str(record['HOSTNAME']) + '\','\
                    'DTYPE=\'' + str(record['DTYPE']) + '\','\
                    'VENDOR=\'' + str(record['VENDOR']) + '\','\
                    'STATUS=\'' + str(record['STATUS']) + '\','\
                    'UPTIME=' + str(record['UPTIME']) + ','\
                    'OSNAME=\'' + str(record['OSNAME']) + '\','\
                    'ACCURACY=' + str(record['ACCURACY']) + ','\
                    'CPE=\'' + str(record['CPE']) + '\','\
                    'PORTUSED=\'' + str(record['PORTUSED']) + '\' '\
                    'WHERE IPv4=\'' + str(record['IPv4']) + '\''
        try:
            cursor.execute(statement)
        except:
            print(statement)
            print('Update record error with ' + record['IPv4'] + ' ......\n')
            db.rollback()
            sys.exit(0)
    db.commit()
    print('Update records completed!\n')


def query(db, cursor, table_name, condition, pattern):
    statement = 'SELECT ' + pattern + ' FROM ' + table_name + ' WHERE ' + condition
    print(statement,'\n')
    cursor.execute(statement)
    result = cursor.fetchall()
    print(result,'\n')
    print('Query completed!\n')
 

if __name__ == '__main__': 
    db = pymysql.connect(host='127.0.0.1', user='root', passwd='123456', charset='utf8')
    cursor = db.cursor()
    db_name = 'thu_ip'
    table_name = 'ip_res'
    table_head ='''(IPv4 CHAR(20) DEFAULT '0.0.0.0',
                    HOSTNAME VARCHAR(50) DEFAULT NULL,
                    DTYPE VARCHAR(20) DEFAULT NULL,
                    VENDOR VARCHAR(100) DEFAULT NULL,
                    STATUS CHAR(10) DEFAULT 'down',
                    UPTIME FLOAT DEFAULT NULL,
                    OSNAME VARCHAR(200) DEFAULT NULL,
                    ACCURACY TINYINT DEFAULT 0,
                    CPE VARCHAR(500) DEFAULT NULL,
                    PORTUSED VARCHAR(1000) DEFAULT NULL,
                    PRIMARY KEY (IPV4))'''
    creat_table(cursor, db_name, table_name, table_head)
    IP_spaces = ['59.66.0-255.0-255',
                 '166.111.0-255.0-255',
                 '118.229.0-31.0-255',
                 '183.172.0-255.0-255',
                 '183.173.0-255.0-255',
                 '101.5.0-255.0-255',
                 '101.6.0-255.0-255']
    init_table(db, cursor, table_name, IP_spaces)
    cursor.execute('USE ' + db_name)
    json_dir = './first_results/'
    # json_dir = './nmap_results/'
    file_lists = os.listdir(json_dir)
    for json_file in file_lists:
        records = read_json(json_dir, json_file)
        update(db, cursor, table_name, records)
    # query(db, cursor, table_name, 'IPv4=\'118.229.14.34\'', 'IPv4,STATUS,UPTIME,OSNAME,ACCURACY')
    # query(db, cursor, table_name, 'STATUS=\'up\'', 'IPv4')
    # query(db, cursor, table_name, 'STATUS=\'up\'', 'COUNT(*)')
    cursor.close()
    db.close()
    