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
CLEAN_INTERVAL = 600  # 清理黑名單的間隔，單位為秒

# 定義全局變量
ip_addresses = []
http_requests = {}
request_history = deque(maxlen=REQUEST_HISTORY_LIMIT)
blacklist = []
whitelist = ['127.0.0.1']

# 定義正則表達式
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
NODE_REGEX = re.compile(r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')


def is_ip_suspicious(ip_address):
    #檢查IP地址是否可疑
    if ip_address in whitelist:
        return False
    if http_requests.get(ip_address, 0) > IP_THRESHOLD:
        return True
    return False


def is_node_suspicious(ip_address):
    #檢查節點ID是否可疑
    for request in request_history:
        if request['ip_address'] == ip_address and NODE_REGEX.match(request['http_path']):
            node_id = request['http_path'].split('/')[-1]
            if [node_id, ip_address] in blacklist:
                return True
            if [node_id, ip_address] in whitelist:
                return False
            if sum([1 for r in request_history if r['ip_address'] == ip_address and r['http_path'].endswith(node_id)]) > NODE_THRESHOLD:
                return True
            break
    return False


def is_syn_flood_attack(ip_address):
    #檢查是否為SYN Flood攻擊
    for request in request_history:
        if request['ip_address'] == ip_address and request['syn_flag']:
            if sum([1 for r in request_history if r['ip_address'] == ip_address and r['syn_flag']]) > SYN_FLOOD_THRESHOLD:
                return True
            break
    return False


def is_udp_flood_attack(ip_address)
    #檢查是否為UDP Flood攻擊
    for request in request_history:
        if request['ip_address'] == ip_address and request['udp_flag']:
            if sum([1 for r in request_history if r['ip_address'] == ip_address and r['udp_flag']]) > UDP_FLOOD_THRESHOLD:
                return True
            break
    return False


def add_to_blacklist(ip_address):
    #將IP地址添加到黑名單中
    global blacklist
    if ip_address not in blacklist:
        logging.warning('Adding IP address to blacklist: %s', ip_address)
        blacklist.append(ip_address)
        # 同時將相應的節點ID添加到黑名單中
        for request in request_history:
            if request['ip_address'] == ip_address and NODE_REGEX.match(request['http_path']):
                node_id = request['http_path'].split('/')[-1]
                if [node_id, ip_address] not in blacklist:
                    blacklist.append([node_id, ip_address])


def add_to_whitelist(ip_address):
    #將IP地址添加到白名單中
    global whitelist
    if ip_address not in whitelist:
        logging.info('Adding IP address to whitelist: %s', ip_address)
        whitelist.append(ip_address)


def handle_request(sock, ip_address):
    #處理HTTP請求
    # 解析HTTP請求
    data = sock.recv(1024)
    headers = data.decode().split('\r\n')
    http_method, http_path, http_version = headers[0].split()
    logging.debug('Received request: %s %s %s', http_method, http_path, http_version)
    syn_flag = False
    udp_flag = False
    for header in headers:
        if header.startswith('Host:'):
            ip_address = IP_REGEX.search(header).group()
        elif header.startswith('User-Agent:') and 'curl' in header:
            add_to_whitelist(ip_address)
        elif header.startswith('Connection:') and header.endswith('close'):
            add_to_whitelist(ip_address)
        elif header.startswith('Connection:') and header.endswith('keep-alive'):
            add_to_whitelist(ip_address)
        # 檢查是否為可疑攻擊
        elif header.startswith('Referer:') and IP_REGEX.search(header):
            referrer_ip = IP_REGEX.search(header).group()
            if referrer_ip != ip_address:
                add_to_blacklist(ip_address)
                sock.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                logging.warning('Blocked suspicious request from %s to %s', referrer_ip, ip_address)
                return
        elif header.startswith('X-Forwarded-For:'):
            xff_ip = IP_REGEX.search(header).group()
            if xff_ip != ip_address:
                add_to_blacklist(ip_address)
                sock.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                logging.warning('Blocked suspicious request from %s to %s', xff_ip, ip_address)
                return
        elif header.startswith('SYN Flag:'):
            syn_flag = True
        elif header.startswith('UDP Flag:'):
            udp_flag = True
    # 將請求添加到歷史記錄中
    http_request = {
        'ip_address': ip_address,
        'http_method': http_method,
        'http_path': http_path,
        'http_version': http_version,
        'syn_flag': syn_flag,
        'udp_flag': udp_flag,
        'timestamp': time.time()
    }
    http_requests[ip_address] = http_requests.get(ip_address, 0) + 1
    request_history.append(http_request)
    # 檢查是否為攻擊
    if is_ip_suspicious(ip_address) or is_node_suspicious(ip_address) or is_syn_flood_attack(ip_address) or is_udp_flood_attack(ip_address):
        add_to_blacklist(ip_address)
        sock.send(b'HTTP/1.1 403 Forbidden\r\n\r\n')
        logging.warning('Blocked suspicious request from %s', ip_address)
        return
    # 處理HTTP請求
    response_body = 'Hello World!'
    response = f'HTTP/1.1 200 OK\r\nContent-Length: {len(response_body)}\r\n\r\n{response_body}'
    sock.send(response.encode())
    logging.debug('Sent response: %s', response)


def learn_from_requests():
    #從HTTP請求中學習攻擊模式
    global blacklist
    global whitelist
    # 檢查黑名單中的IP地址是否過期
    for i, item in enumerate(blacklist):
        if isinstance(item, list):
            node_id, ip_address = item
            if ip_address not in ip_addresses:
                blacklist.pop(i)
        elif item not in ip_addresses:
            blacklist.pop(i)
    # 檢查白名單中的IP地址是否過期
    for i, item in enumerate(whitelist):
        if item not in ip_addresses:
            whitelist.pop(i)
    # 分析最近的HTTP請求歷史
    ip_counts = {}
    node_counts = {}
    for request in request_history:
        ip_address = request['ip_address']
        http_path = request['http_path']
        if ip_address not in ip_counts:
            ip_counts[ip_address] = 0
        ip_counts[ip_address] += 1
        if NODE_REGEX.match(http_path):
            node_id = http_path.split('/')[-1]
            if ip_address not in node_counts:
                node_counts[ip_address] = {}
            if node_id not in node_counts[ip_address]:
                node_counts[ip_address][node_id] = 0
            node_counts
            [node_id] += 1
    # 檢查IP地址的HTTP請求次數是否超過閾值
    for ip_address in ip_counts:
        if ip_counts[ip_address] >= IP_HTTP_THRESHOLD:
            add_to_blacklist(ip_address)
            logging.warning('Added IP address to blacklist due to excessive HTTP requests: %s', ip_address)
    # 檢查節點的HTTP請求次數是否超過閾值
    for ip_address in node_counts:
        for node_id in node_counts[ip_address]:
            if node_counts[ip_address][node_id] >= NODE_HTTP_THRESHOLD:
                add_to_blacklist(ip_address)
                logging.warning('Added IP address to blacklist due to excessive HTTP requests to node %s: %s', node_id, ip_address)
    # 檢查SYN Flag是否達到閾值
    for ip_address in syn_flags:
        if syn_flags[ip_address] >= SYN_THRESHOLD:
            add_to_blacklist(ip_address)
            logging.warning('Added IP address to blacklist due to excessive SYN flags: %s', ip_address)
    # 檢查UDP Flag是否達到閾值
    for ip_address in udp_flags:
        if udp_flags[ip_address] >= UDP_THRESHOLD:
            add_to_blacklist(ip_address)
            logging.warning('Added IP address to blacklist due to excessive UDP flags: %s', ip_address)


def main():
    #主函數
    # 啟動HTTP服務器
    logging.info('Starting HTTP server on port %d', HTTP_PORT)
    http_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_server.bind(('0.0.0.0', HTTP_PORT))
    http_server.listen(5)
    # 循環處理HTTP請求
    while True:
        sock, address = http_server.accept()
        ip_address = address[0]
        logging.debug('Received connection from %s', ip_address)
        handle_request(sock, ip_address)
        learn_from_requests()
        sock.close()


if __name__ == '__main__':
    main()
