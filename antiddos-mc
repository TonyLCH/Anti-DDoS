import socket
import struct
import time
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

# 防禦時間間隔（秒）
BLOCK_TIME = 60

# 記錄攻擊者IP地址的字典
attackers = {}

# 機器學習算法模型
models = [IsolationForest(), OneClassSVM(), DecisionTreeClassifier(), RandomForestClassifier()]

# 防禦策略參數
DEFENSE_PARAMETERS = {
    'time_window': 5,  # 時間窗口大小（秒）
    'attack_threshold': 10,  # 攻擊頻率閾值（次/秒）
    'attack_strength_threshold': 50,  # 攻擊強度閾值（Mbps）
    'block_time_factor': 2,  # 封鎖時間因子
    'block_time_min': 20,  # 最小封鎖時間（秒）
    'block_time_max': 600,  # 最大封鎖時間（秒）
}

def block_attacker(ip_address, block_time):
    #封鎖攻擊者IP地址
    # TODO: 將封鎖攻擊者IP地址的代碼替換成Minecraft伺服器的具體實現
    print(f"Blocking attacker {ip_address} for {block_time} seconds")

def unblock_attacker(ip_address):
    #解封攻擊者IP地址
    # TODO: 將解封攻擊者IP地址的代碼替換成Minecraft伺服器的具體實現
    print(f"Unblocking attacker {ip_address}")

def handle_attack(sock, ip_address):
    #處理DDoS攻擊
    if ip_address in attackers:
        # 如果攻擊者已經被封鎖，則直接返回
        if time.time() - attackers[ip_address]['block_time'] < attackers[ip_address]['block_duration']:
            return
        # 否則解封攻擊者IP地址
        else:
            unblock_attacker(ip_address)

    # 獲取當前時間
    now = time.time()

    # 將攻擊流量轉換為Mbps
    attack_strength = struct.unpack('!Q', data[:8])[0] * 8 / 1000000

    # 更新攻擊者字典
    if ip_address not in attackers:
        attackers[ip_address] = {
            'attack_history': [],
            'last_attack_time': now
        }
    else:
        # 計算攻擊頻率和攻擊強度
        attack_frequency = 1 / (now - attackers[ip_address]['last_attack_time'])
        attackers[ip_address]['attack_history'].append((now, attack_frequency, attack_strength))
        attackers[ip_address]['attack_history'] = [x for x in attackers[ip_address]['attack_history'] if now - x[0] <= DEFENSE_PARAMETERS['time_window']]
        attack_frequency_avg = sum([x[1] for x in attackers[ip_address]['attack_history']]) / len(attackers[ip_address]['attack_history'])
        attack_strength_avg = sum([x[2] for x in attackers[ip_address]['attack_history']]) / len(attackers[ip_address]['attack_history'])

        # 使用機器學習算法檢測攻擊
        for model in models:
            if model.predict([[attack_frequency_avg, attack_strength_avg]])[0] == -1:
                # 如果是攻擊，則進行防禦
                block_time = min(max(int(attack_frequency_avg * attack_strength_avg * DEFENSE_PARAMETERS['block_time_factor']), DEFENSE_PARAMETERS['block_time_min']), DEFENSE_PARAMETERS['block_time_max'])
                block_attacker(ip_address, block_time)
                attackers[ip_address]['block_time'] = now
                attackers[ip_address]['block_duration'] = block_time
                return

    # 更新攻擊者的最後攻擊時間
    attackers
    [ip_address]['last_attack_time'] = now

def main():
    # 創建socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 25565))

    while True:
        data, addr = sock.recvfrom(1024)
        ip_address = addr[0]

        # 處理攻擊
        handle_attack(sock, ip_address)

if __name__ == '__main__':
    main()
