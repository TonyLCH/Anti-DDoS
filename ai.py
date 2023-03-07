import socket
import logging
import numpy as np
from keras.models import Sequential
from keras.layers import Dense, Dropout, Flatten
from keras.layers.convolutional import Conv1D, MaxPooling1D
from keras.utils import np_utils
from sklearn.preprocessing import StandardScaler

# 設置常量
HTTP_PORT = 80
IP_BLACKLIST_DURATION = 60 * 60  # IP地址在黑名單中的持續時間（秒）
IP_WHITE_THRESHOLD = 10  # IP地址在白名單中的最小出現次數
IP_HTTP_THRESHOLD = 20  # IP地址的HTTP請求次數閾值
NODE_HTTP_THRESHOLD = 10  # 節點的HTTP請求次數閾值
SYN_THRESHOLD = 100  # SYN Flag的閾值
UDP_THRESHOLD = 1000  # UDP Flag的閾值

# 定義全局變量
ip_blacklist = {}  # IP地址黑名單，格式：{ip_address: expiration_time}
ip_whitelist = {}  # IP地址白名單，格式：{ip_address: count}
ip_counts = {}  # IP地址的HTTP請求次數，格式：{ip_address: count}
node_counts = {}  # 節點的HTTP請求次數，格式：{ip_address: {node_id: count}}
syn_flags = {}  # SYN Flag的次數，格式：{ip_address: count}
udp_flags = {}  # UDP Flag的次數，格式：{ip_address: count}
model = None  # 深度學習模型


def add_to_blacklist(ip_address):
    #將IP地址添加到黑名單中
    logging.warning('Adding IP address to blacklist: %s', ip_address)
    ip_blacklist[ip_address] = int(time.time()) + IP_BLACKLIST_DURATION


def add_to_whitelist(ip_address):
    #將IP地址添加到白名單中
    logging.debug('Adding IP address to whitelist: %s', ip_address)
    if ip_address in ip_whitelist:
        ip_whitelist[ip_address] += 1
    else:
        ip_whitelist[ip_address] = 1


def handle_request(sock, ip_address):
    #處理HTTP請求
    # 檢查IP地址是否在黑名單中
    if ip_address in ip_blacklist:
        expiration_time = ip_blacklist[ip_address]
        if time.time() < expiration_time:
            logging.warning('IP address is in blacklist: %s', ip_address)
            sock.close()
            return
        else:
            logging.debug('Removing IP address from blacklist: %s', ip_address)
            del ip_blacklist[ip_address]
    # 檢查IP地址是否在白名單中
    if ip_address in ip_whitelist:
        count = ip_whitelist[ip_address]
        if count >= IP_WHITE_THRESHOLD:
            logging.debug('IP address is in whitelist: %s', ip_address)
        else:
            add_to_whitelist(ip_address)
    # 解析HTTP請求內容
    request = sock.recv(1024)
    logging.debug('Received HTTP request from %s: %s', ip_address, request)
    # 檢查是否是SYN Flood攻擊
    if 'SYN' in request:
        if ip_address in syn_flags:
            syn_flags[ip_address] += 1
        else:
            syn_flags[ip_address] = 1
    # 檢查是否是UDP Flood攻擊
    if 'UDP' in request:
        if ip_address in udp_flags:
            udp_flags[ip_address] += 1
        else:
            udp_flags[ip_address] = 1
    # 更新IP地址的HTTP請求次數
    if ip_address in ip_counts:
        ip_counts[ip_address] += 1
    else:
        ip_counts[ip_address] = 1
    # 更新節點的HTTP請求次數
    node_id = request.split()[1]
    if ip_address in node_counts:
        if node_id in node_counts[ip_address]:
            node_counts[ip_address][node_id] += 1
        else:
            node_counts
            [ip_address][node_id] = 1
    else:
        node_counts[ip_address] = {node_id: 1}
    # 檢查IP地址的HTTP請求次數是否超過閾值
    if ip_address in ip_counts:
        count = ip_counts[ip_address]
        if count >= IP_HTTP_THRESHOLD:
            logging.warning('IP address is sending too many HTTP requests: %s', ip_address)
            add_to_blacklist(ip_address)
    # 檢查節點的HTTP請求次數是否超過閾值
    if ip_address in node_counts:
        for node_id, count in node_counts[ip_address].items():
            if count >= NODE_HTTP_THRESHOLD:
                logging.warning('Node is sending too many HTTP requests: %s:%s', ip_address, node_id)
                add_to_blacklist(ip_address)
    # 檢查是否是攻擊
    if is_attack(ip_address):
        logging.warning('Detected attack from IP address: %s', ip_address)
        add_to_blacklist(ip_address)
    # 發送HTTP響應
    response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello, world!'
    sock.sendall(response)
    sock.close()


def is_attack(ip_address):
    #檢查是否是攻擊
    # 檢查是否是SYN Flood攻擊
    if ip_address in syn_flags and syn_flags[ip_address] >= SYN_THRESHOLD:
        logging.warning('Detected SYN Flood attack from IP address: %s', ip_address)
        return True
    # 檢查是否是UDP Flood攻擊
    if ip_address in udp_flags and udp_flags[ip_address] >= UDP_THRESHOLD:
        logging.warning('Detected UDP Flood attack from IP address: %s', ip_address)
        return True
    # 檢查是否是DDoS攻擊
    if is_ddos(ip_address):
        return True
    # 檢查是否是SQL注入攻擊
    if is_sql_injection(ip_address):
        return True
    # 檢查是否是XSS攻擊
    if is_xss(ip_address):
        return True
    return False


def is_ddos(ip_address):
    #檢查是否是DDoS攻擊
    # 準備訓練數據
    X = []
    for i in range(10):
        if ip_address in ip_counts:
            count = ip_counts[ip_address]
            X.append(count)
        else:
            X.append(0)
        time.sleep(1)
    X = np.array(X).reshape(1, -1)
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    # 使用深度學習模型進行預測
    y_pred = model.predict(X)
    if y_pred[0][0] > 0.5:
        logging.warning('Detected DDoS attack from IP address: %s', ip_address)
        return True
    return False


def is_sql_injection(ip_address):
    #檢查是否是SQL注入攻擊
    # TODO: 實現SQL注入攻擊檢測邏輯
    return False


def is_xss(ip_address):
    #檢查是否是XSS攻擊
    # TODO: 實現XSS攻擊檢測邏輯
    return False


def train_model():
    #訓練深度學習模型
    X = []
    y = []
    for ip_address, count in ip_counts.items():
        X.append(count)
        if ip_address in ip_blacklist:
            y.append(1)
        else:
            y.append(0)
    X = np.array(X).reshape(-1, 1)
    y = np.array(y).reshape(-1, 1)
    y = np_utils.to_categorical(y)
    model = Sequential()
    model.add(Dense(32, input_dim=1, activation='relu'))
    model.add(Dense(2, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(X, y, epochs=10, batch_size=32, verbose=1)
    return model


if __name__ == '__main__':
    # 訓練深度學習模型
    logging.info('Training deep learning model...')
    model = train_model()
    logging.info('Training complete.')
    # 啟動HTTP服務器
    logging.info('Starting HTTP server...')
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', HTTP_PORT))
    server_socket.listen(0)
    while True:
        client_socket, address = server_socket.accept()
        ip_address = address[0]
        logging.debug('Accepted connection from %s', ip_address)
        handle_request(client_socket, ip_address)
