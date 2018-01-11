#!/usr/bin/python
#-*- coding: utf-8 -*-

'''
先用masscan快速扫描开放的端口
再用nmap识别开放端口的服务版本
'''

import nmap
import os
import sys
import re
import threading
import queue
import time
import optparse
import xlwt
from colorama import Fore

class Scan():

    # 定义全局变量
    def __init__(self,scanip,scanport,threadnum):
        self.scanip = scanip
        self.scanport = scanport
        self.scannum = threadnum
        self.info_ip = {}
        self.info_port = {}
        self.order = 1
        self.xlwtwork = ''
        self.ws = ''

    # masscan快速扫描开放的端口
    def Masscan_port(self):
        print(Fore.GREEN + '\n\n[+] Masscan 开始.' + Fore.RESET)
        # 用os库调用系统安装的masscan进行扫描
        if(os.name == 'posix'):
            # --rate 1000 发包速 1000 --wait 扫描全部结束后等待3秒用于接受剩余返回包
            mscan = os.popen('./masscan/masscan --rate 1000 --wait 3 -p ' + self.scanport + ' ' + self.scanip)
        else:
            print(Fore.RED + '\n[-] 仅支持linux' + Fore.RESET)
            sys.exit(0)
        mscanresule = mscan.read()
        mscaninfolist = mscanresule.strip('\n').split('\n')
        for info in mscaninfolist:
            # 利用正则从masscan的扫描信息中过滤端口和IP地址
            reinfo = re.search(re.compile(r'Discovered open port (\d+?)/tcp on (.*)'),info.strip(' '))
            if(reinfo == None):
                print(Fore.RED + '\n[-] 该网段无符合条件主机.')
                sys.exit(0)
            # 以IP地址为单位统计端口开放信息
            if(reinfo.group(2) in self.info_ip):
                self.info_ip[reinfo.group(2)].append(reinfo.group(1))
            else:
                lis = [reinfo.group(1)]
                self.info_ip[reinfo.group(2)] = lis
            # 以端口为单位统计端口开放信息
            if(reinfo.group(1) in self.info_port):
                self.info_port[reinfo.group(1)].append(reinfo.group(2))
            else:
                lis = [reinfo.group(2)]
                self.info_port[reinfo.group(1)] = lis
        self.Print_count()

    # 分别从info_ip和info_port统计端口开放信息
    def Print_count(self):
        print(Fore.GREEN + '\n[+] 活跃IP共 ' + str(len(self.info_ip.keys())) + '个.\n')
        for ip in self.info_ip.keys():
            print(Fore.BLUE + '     ' + ip)
        for port in self.info_port.keys():
            print(Fore.GREEN + '\n[+] 开放 ' + port + ' 端口的共 ' + str(len(self.info_port[port])) + ' 个.\n')
            for ip in self.info_port[port]:
                print(Fore.BLUE + '     ' + ip)

    # nmap识别开放端口的服务版本
    def Nmapscan_sV(self):
        print(Fore.GREEN + '\n\n[+] Nmap 开始.\n' + Fore.RESET)
        # 设定线程锁，防止shell中输出混乱
        lock = threading.Lock()
        # 通过队列threads1和threads2实现多线程的调用
        threads1 = queue.Queue()
        threads2 = queue.Queue()
        self.xlwtwork = xlwt.Workbook(encoding='utf-8')
        self.ws = self.xlwtwork.add_sheet('info')
        self.ws.write(0, 0, 'IP')
        self.ws.write(0, 1, '操作系统版本')
        self.ws.write(0, 2, '端口')
        self.ws.write(0, 3, '服务')
        self.ws.write(0, 4, '服务版本')
        for ip in self.info_ip.keys():
            threads1.put(threading.Thread(target=self.nmscans, args=(ip,lock)))
        for i in range(1,threads1.qsize()+1):
            que = threads1.get()
            que.setDaemon(False)
            que.start()
            threads2.put(que)
            if(i % int(self.scannum) == 0):
                time.sleep(4)
        threads2.get().join(20)

    # nmap扫描函数
    def nmscans(self,ip,lock):
        infos = []
        nmscan = nmap.PortScanner()
        for port in self.info_ip[ip]:
            try:
                # nmap扫描参数 --host-timeout 18:超时时间 -T5:快速 -Pn:不ping -sV:端口对应服务版本 -O:系统指纹识别
                nminfo = nmscan.scan(hosts=ip, ports=port, arguments='--host-timeout 20 -T5 -Pn -sV -O')
            except TimeoutError:
                pass
            try:
                nmserver = nminfo['scan'][ip]['osmatch'][0]['name']
                nmname = nminfo['scan'][ip]['tcp'][int(port)]['name']
                nmproduct = nminfo['scan'][ip]['tcp'][int(port)]['product']
                nmversion = nminfo['scan'][ip]['tcp'][int(port)]['version']
            except:
                # 因超时丢弃一些端口，导致参数获取不到信息，就置为空
                nmserver = ''
                nmname = ''
                nmproduct = ''
                nmversion = ''
            info = []
            info.append(ip)
            info.append(nmserver)
            info.append(port)
            info.append(nmname)
            info.append(nmproduct)
            info.append(nmversion)
            infos.append(info)
        lock.acquire()
        self.Print_info(infos)
        lock.release()

    # 扫描信息输出
    def Print_info(self,infos):
        print(Fore.BLUE + '     ' + infos[0][0] + ' 操作系统指纹：' + infos[0][1])
        print(Fore.BLUE + '     端口信息：')
        print(Fore.BLUE + '     -----------------------------------------------------------------------------------')
        for i in range(0,len(infos),1):
            print(Fore.BLUE + '    | ' + '端口：' + str(infos[i][2]) + '   服务：' + str(infos[i][3]) + '  版本：' + str(infos[i][4]) + '    ' + str(infos[i][5]))
            self.ws.write(self.order, 0, infos[i][0])
            self.ws.write(self.order, 1, infos[i][1])
            self.ws.write(self.order, 2, infos[i][2])
            self.ws.write(self.order, 3, infos[i][3])
            self.ws.write(self.order, 4, infos[i][4] + infos[i][5])
            self.order = self.order + 1
        print(Fore.BLUE + '     -----------------------------------------------------------------------------------\n')
        self.xlwtwork.save('./scaninfo.xls')

def Display():
    print(Fore.BLUE + '    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
    print(Fore.BLUE + '    +  usege:                                                                +')
    print(Fore.BLUE + '    +       python3 scan.py -H 192.168.1.1 -P 22 -N 10                       +')
    print(Fore.BLUE + '    +       python3 scan.py -H 192.168.1.1/24 -P 22,80 -N 10                 +')
    print(Fore.BLUE + '    +       python3 scan.py -H 192.168.1.1/24 -P 22-25 -N 10                 +')
    print(Fore.BLUE + '    +       python3 scan.py -H 192.168.1.1-192.168.1.254 -P 22,80 -N 10      +')
    print(Fore.BLUE + '    +       python3 scan.py -H 192.168.1.1-192.168.254.1 -P 22-25 -N 10      +')
    print(Fore.BLUE + '    +       python3 scan.py -H 192.167.1.1-192.168.1.1 -P 22-25 -N 10        +')
    print(Fore.BLUE + '    ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


if __name__ == '__main__':

    print(Fore.YELLOW + os.popen('figlet XiaoRui-Scan').read() + Fore.RESET)
    parser = optparse.OptionParser('    usage%prog ' + '-H <RHOST[S]> -P <PORT[S]> -N <THREADS>')
    parser.add_option('-H', dest='hosts', type='string', help='单个IP或IP段')
    parser.add_option('-P', dest='ports', type='string', help='单个或多个端口')
    parser.add_option('-N', dest='num', type='int', help='线程分组中的线程数')
    (options, args) = parser.parse_args()
    if (options.hosts == None) | (options.ports == None) | (options.num == None):
        print(parser.usage)
        Display()
        exit(0)
    # 输出的IP或IP段
    ip = options.hosts
    # 输入的端口
    port = options.ports
    # 输入的分组个数
    threadnum = options.num
    # 调用Scan类进行扫描
    scan = Scan(scanip=ip, scanport=port , threadnum = threadnum)
    # 进行masscan快速端口扫描
    scan.Masscan_port()
    # 进行nmap扫描和指纹识别
    scan.Nmapscan_sV()
