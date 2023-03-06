好的，我們可以針對這些方面進行改進。以下是改進的程式碼：

```python
import socket
import threading
import time
import json
import re
import logging
from collections import deque
from typing import List, Dict

# 防禦參數
HOST = '0.0.0.0'  # 監聽IP地址
PORT = 8080  # 監聽端口
BACKLOG = 50  # 最大連接數
IP_THRESHOLD = 100  # 攻擊IP閾值
NODE_THRESHOLD = 10  # 攻擊頻率節點閾值
REQUEST_LIMIT = 100  # 單個IP地址的最大請求數量
REQUEST_HISTORY_LIMIT = 1000  # 記錄請求歷史的最大數量
CLEAN_INTERVAL = 60  # 定期清理計數器和名單的時間間隔（秒）
LEARNING_RATE = 0.1  # 自學習速率
MAX_BLACKLIST_SIZE = 10000  # 黑名單最大數量
MAX_WHITELIST_SIZE = 10000  # 白名單最大數量
BLACKLIST_CLEAN_INTERVAL = 3600  # 清理黑名單的時間間隔（秒）
WHITELIST_CLEAN_INTERVAL = 3600  # 清理白名單的時間間隔（秒）
SYN_FLOOD_THRESHOLD = 20  # SYN Flood攻擊閾值
UDP_FLOOD_THRESHOLD = 10000  # UDP Flood攻擊閾值

# 防禦狀態
http_requests = {}  # 記錄IP地址的HTTP請求數量
ip_addresses = []  # 記錄攻擊IP地址和時間
blacklist = deque(maxlen=MAX_BLACKLIST_SIZE)  # 黑名單
whitelist = deque(maxlen=MAX_WHITELIST_SIZE)  # 白名單
request_history = deque(maxlen=REQUEST_HISTORY_LIMIT)  # 記錄請求歷史

# 日誌配置
logging.basicConfig(filename='ddos_protection.log', level=logging.WARNING,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def block_ip_address(ip_address: str):
    #將IP地址加入黑名單
    if ip_address not in blacklist:
        blacklist.append(ip_address)
        if ip_address in whitelist:
            whitelist.remove(ip_address)
        logging.warning('Blocked IP address: %s', ip_address)


def unblock_ip_address(ip_address: str):
    #將IP地址從黑名單中移除
    if ip_address in blacklist:
        blacklist.remove(ip_address)
        logging.warning('Unblocked IP address: %s', ip_address)


def add_to_whitelist(ip_address: str):
    #將IP地址加入白名單
    if ip_address not in whitelist:
        whitelist.append(ip_address)
        if ip_address in blacklist:
            blacklist.remove(ip_address)
        logging.warning('Whitelisted IP address: %s', ip_address)


def clean_http_requests():
    #清理HTTP請求計數器
    for ip_address in list(http_requests.keys()):
        if http_requests[ip_address] == 0:
            http_requests.pop(ip_address)
        else:
            http_requests[ip_address] -= 1


def clean_ip_addresses():
    #清理攻擊IP地址記錄
    global ip_addresses
    now = time.time()
    ip_addresses = [ip for ip in ip_addresses if now - ip['time'] <= IP_THRESHOLD]


def clean_blacklist():
    #清理黑名單
    global blacklist
    now = time.time()
    blacklist = deque([ip for ip in blacklist if now - ip['time'] <= BLACKLIST_CLEAN_INTERVAL],
                      maxlen=MAX_BLACKLIST_SIZE)


def clean_whitelist():
    #清理白名單
    global whitelist
    now = time.time()
    whitelist = deque([ip for ip in whitelist if now - ip['time'] <= WHITELIST_CLEAN_INTERVAL],
                       maxlen=MAX_WHITELIST_SIZE)


def clean_request_history():
    #清理請求歷史
    global request_history
    now = time.time()
    request_history = deque([req for req in request_history if now - req['time'] <= CLEAN_INTERVAL],
                            maxlen=REQUEST_HISTORY_LIMIT)


def update_request_history(ip_address: str):
    #更新請求歷史
    request_history.append({'ip_address': ip_address, 'time': time.time()})


def is_syn_flood_attack(ip_address: str) -> bool:
    #檢查是否為SYN Flood攻擊
    count = 0
    for req in request_history:
        if req['ip_address'] == ip_address and 'SYN' in req['request']:
            count += 1
            if count >= SYN_FLOOD_THRESHOLD:
                return True
    return False


def is_udp_flood_attack(ip_address: str) -> bool:
    #檢查是否為UDP Flood攻擊
    count = 0
    for req in request_history:
        if req['ip_address'] == ip_address and 'UDP' in req['request']:
            count += 1
            if count >= UDP_FLOOD_THRESHOLD:
                return True
    return False


def is_attack(ip_address: str) -> bool:
    #檢查是否為攻擊
    if len(ip_addresses) >= IP_THRESHOLD:
        return True
    node_count = 0
    for ip in ip_addresses:
        if ip['ip_address'] == ip_address:
            node_count += 1
            if node_count >= NODE_THRESHOLD:
                return True
    return False


def is_on_blacklist(ip_address: str) -> bool:
    #檢查IP地址是否在黑名單中
    return ip_address in blacklist


def is_on_whitelist(ip_address: str) -> bool:
    #檢查IP地址是否在白名單中
    return ip_address in whitelist


def learn(ip_address: str, request: str):
    #自學習
    if ip_address in http_requests:
        http_requests[ip_address] += 1
    else:
        http_requests[ip_address] = 1
    update_request_history(ip_address)
    if is_syn_flood_attack(ip_address):
        block_ip_address(ip_address)
    elif is_udp_flood_attack(ip_address):
        block_ip_address(ip_address)
    elif is_attack(ip_address):
        block_ip_address(ip_address)
    elif http_requests[ip_address] >= REQUEST_LIMIT:
        block_ip_address(ip_address)


def handle_request(sock: socket.socket, ip_address: str):
    #處理請求
    try:
        request = sock.recv(1024).decode('utf-8')
        if not request:
            return
        if is_on_blacklist(ip_address):
            logging.warning('Blocked request from blacklisted IP address: %s', ip_address)
            return
        if is_on_whitelist(ip_address):
            logging.warning('Allowed request from whitelisted IP address: %s', ip_address)
            sock.sendall('HTTP/1.1 200 OK\n\n'.encode('utf-8'))
            return
        if request.startswith('GET / HTTP/1.1'):
            sock.sendall('HTTP/1.1 200 OK\n\n'.encode('utf-8'))
            return
        if request.startswith('POST /login HTTP/1.1'):
            match = re.search(r'username=([^&]+)&password=([^&]+)', request)
            if match:
                username = match.group(1)
                password = match.group(2)
                if username == 'admin' and password == 'admin':
                    add_to_whitelist(ip_address)
                    logging.warning('Added IP address to whitelist: %s', ip_address)
            sock.sendall('HTTP/1.1 200 OK\n\n'.encode('utf-8'))
            return
        learn(ip_address, request)
        sock.sendall('HTTP/1.1 200 OK\n\n'.encode('utf-8'))
    except Exception as e:
        logging.warning('Error handling request: %s', e)
    finally:
        sock.close()


def main():
    #主函數
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(BACKLOG)
    logging.warning('Server started')
    while True:
        try:
            sock, address = server_sock.accept()
            ip_address = address[0]
            ip_addresses.append({'ip_address': ip_address, 'time': time.time()})
            threading.Thread
            (target=handle_request, args=(sock, ip_address)).start()
            cleanup_request_history()
        except KeyboardInterrupt:
            logging.warning('Server stopped')
            break


if __name__ == '__main__':
    main()
    
