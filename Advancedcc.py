import socket
import scapy.all as scapy
import re
import subprocess
import threading
import time

# 監聽端口
HOST = ''
PORT = 80
BACKLOG = 5

# 設置iptables規則的命令
IPTABLES_CMD = 'iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 10 -j DROP'

# 設置攔截閾值和攔截時間
REQUEST_THRESHOLD = 50
REQUEST_BLOCK_TIME = 300
IP_THRESHOLD = 100
IP_BLOCK_TIME = 600

# 設置計數器和請求列表
http_requests = {}
ip_addresses = []

# 設置黑名單和白名單
blacklist = {}
whitelist = set()

# 設置定期清理計數器和名單的時間間隔
CLEAN_INTERVAL = 60

# 創建socket對象
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(BACKLOG)

# 定義清理計數器和名單的函數
def clean():
    while True:
        time.sleep(CLEAN_INTERVAL)
        global http_requests
        global ip_addresses
        global blacklist
        global whitelist
        http_requests = {}
        ip_addresses = []
        for ip_address in blacklist:
            if blacklist[ip_address] < time.time():
                del blacklist[ip_address]
        whitelist = set()

# 定義攔截攻擊的函數
def block(ip_address):
    # 檢查是否在白名單中
    if ip_address in whitelist:
        return
    # 檢查是否已經在黑名單中
    if ip_address in blacklist:
        return
    # 擋住攻擊
    subprocess.call(IPTABLES_CMD.split())
    # 記錄攻擊IP地址和攔截時間
    print(f'Blocked IP address: {ip_address}')
    blacklist[ip_address] = time.time() + IP_BLOCK_TIME

# 定義解析網路流量的函數
def parse_packet(packet):
    if packet.haslayer(scapy.TCP):
        tcp = packet[scapy.TCP]
        if tcp.haslayer(scapy.Raw):
            raw = tcp[scapy.Raw]
            http_data = raw.load.decode('utf-8')
            # 檢查HTTP請求
            if re.match(r'GET /path/to/resource HTTP/1.[01]', http_data):
                # 記錄IP地址和請求
                ip_address = packet[scapy.IP].src
                ip_addresses.append(ip_address)
                if ip_address in http_requests:
                    http_requests[ip_address] += 1
                    if http_requests[ip_address] > REQUEST_THRESHOLD:
                        # 攔截攻擊
                        block(ip_address)
                else:
                    http_requests[ip_address] = 1
                # 判斷是否存在大量相同的請求
                if ip_addresses.count(ip_address) > IP_THRESHOLD:
                    # 攔截攻擊
                    block(ip_address)

# 定義監聽網路流量的函數
def listen():
    while True:
        conn, addr = sock.accept()
        data = conn.recv(1024)
        # 解析網路流量
        packet = scapy.IP(data)
        parse_packet(packet)
        conn.close()

# 定義清理計數器和名單的線程
clean_thread = threading.Thread(target=clean)
clean_thread.start()

# 啟動監聽網路流量的線程
listen_thread = threading.Thread(target=listen)
listen_thread.start()
