import socket
import threading
import time
import re
import logging
from collections import deque

# 設置常量
HOST = '0.0.0.0'
PORT = 8080
BACKLOG = 5
REQUEST_LIMIT = 10
IP_THRESHOLD = 100
NODE_THRESHOLD = 10
SYN_FLOOD_THRESHOLD = 5
UDP_FLOOD_THRESHOLD = 10
REQUEST_HISTORY_LIMIT = 1000
CLEAN_INTERVAL = 60 * 10  # 10分鐘

# 定義全局變量
ip_addresses = []
http_requests = {}
blacklist = []
whitelist = []
request_history = deque(maxlen=REQUEST_HISTORY_LIMIT)


# 定義函數
def add_to_blacklist(ip_address: str):
    """
    將IP地址添加到黑名單中
    """
    if ip_address not in blacklist:
        blacklist.append(ip_address)
        logging.warning('Added IP address to blacklist: %s', ip_address)


def add_to_whitelist(ip_address: str):
    """
    將IP地址添加到白名單中
    """
    if ip_address not in whitelist:
        whitelist.append(ip_address)
        logging.info('Added IP address to whitelist: %s', ip_address)


def is_ip_suspicious(ip_address: str) -> bool:
    #檢查IP地址是否可疑
    if ip_address in whitelist:
        return False
    count = ip_addresses.count(ip_address)
    if count > IP_THRESHOLD:
        return True
    return False


def is_node_suspicious(ip_address: str) -> bool:
    #檢查節點是否可疑
    if ip_address in whitelist:
        return False
    count = 0
    for ip in ip_addresses:
        if ip.startswith(ip_address):
            count += 1
    if count > NODE_THRESHOLD:
        return True
    return False


def is_syn_flood_attack(ip_address: str) -> bool:
    #檢查是否為SYN Flood攻擊
    if ip_address in whitelist:
        return False
    count = 0
    for http_request in request_history:
        if http_request['ip_address'] == ip_address and http_request['syn_flag']:
            count += 1
    if count > SYN_FLOOD_THRESHOLD:
        return True
    return False


def is_udp_flood_attack(ip_address: str) -> bool:
    #檢查是否為UDP Flood攻擊
    if ip_address in whitelist:
        return False
    count = 0
    for http_request in request_history:
        if http_request['ip_address'] == ip_address and http_request['udp_flag']:
            count += 1
    if count > UDP_FLOOD_THRESHOLD:
        return True
    return False


def handle_request(sock: socket.socket, ip_address: str):
    #處理HTTP請求
    global ip_addresses
    global http_requests
    global blacklist
    global request_history
    # 讀取HTTP請求
    http_request = b''
    while True:
        data = sock.recv(1024)
        if not data:
            break
        http_request += data
        if b'\r\n\r\n' in http_request:
            break
    # 解析HTTP請求
    http_request_str = http_request.decode('utf-8')
    http_method = re.match(r'^([A-Z]+)', http_request_str).group(1)
    http_path = re.match(r'^[A-Z]+\s+([^\s]+)', http_request_str).group(1)
    http_version = re.match(r'^[A-Z]+\s+[^\s]+\s+([^\r]+)', http_request_str).group(1)
    headers = re.findall(r'([^\r]+)\r\n', http_request_str)[1:]
    syn_flag = False
    udp_flag = False
    for header in headers:
        if header.startswith('User-Agent:'):
            user_agent = header.split(':')[1].strip()
            if 'Java/' in user_agent:
                # 檢測到Java User-Agent，可能是Minecraft攻擊，需要進一步檢查是否為SYN Flood攻擊或UDP Flood攻擊
        elif header.startswith('Connection:') and header.endswith('SYN'):
            syn_flag = True
        elif header.startswith('Connection:') and header.endswith('UDP'):
            udp_flag = True
    # 更新全局變量
    ip_addresses.append(ip_address)
    http_requests[ip_address] = http_requests.get(ip_address, 0) + 1
    request_history.append({'ip_address': ip_address, 'http_method': http_method, 'http_path': http_path,
                            'http_version': http_version, 'syn_flag': syn_flag, 'udp_flag': udp_flag})
    # 檢查是否需要加入黑名單
    if is_ip_suspicious(ip_address) or is_node_suspicious(ip_address) or is_syn_flood_attack(ip_address) or is_udp_flood_attack(ip_address):
        add_to_blacklist(ip_address)
        sock.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
        logging.warning('Blocked suspicious request from IP address: %s', ip_address)
    else:
        # 處理HTTP請求
        if http_requests[ip_address] > REQUEST_LIMIT:
            add_to_blacklist(ip_address)
            sock.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            logging.warning('Blocked request from IP address, exceeding request limit: %s', ip_address)
        else:
            sock.send(b'HTTP/1.1 200 OK\r\n\r\n')
            logging.info('Processed request from IP address: %s', ip_address)
    # 關閉socket
    sock.close()


def clean_blacklist():
    #清理黑名單
    global blacklist
    logging.info('Cleaning blacklist...')
    now = time.time()
    blacklist = [ip_address for ip_address in blacklist if now - ip_address[1] < CLEAN_INTERVAL]


def start_server():
    #啟動HTTP伺服器
    # 設置日誌
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    # 創建socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(BACKLOG)
    logging.info('Server started on port %s...', PORT)
    # 循環處理HTTP請求
    while True:
        # 接受socket連接
        sock, addr = server_sock.accept()
        ip_address = addr[0]
        # 清理黑名單
        clean_blacklist()
        # 檢查是否在黑名單中
        if ip_address in blacklist:
            sock.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            logging.warning('Blocked request from blacklisted IP address: %s', ip_address)
            sock.close()
        else:
            # 分配線程處理HTTP請求
            threading.Thread(target=handle_request, args=(sock, ip_address)).start()


if __name__ == '__main__':
    start_server()
