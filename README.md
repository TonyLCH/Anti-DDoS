# Web伺服器DDoS攔截

這是一個基於Python的Web伺服器，它可以檢測並阻擋一些常見的攻擊，如HTTP Flood攻擊、SYN Flood攻擊、UDP Flood攻擊和DoS攻擊。此外，它還具有AI學習功能，可以自動學習攻擊者的行為，並在需要時阻擋它們。

## 系統需求

* Python 3.x
* socket
* re
* logging
* threading

## 使用方法

1. 將腳本下載到本地。

2. 在命令行中運行以下命令以啟動伺服器：

   ```
   python3 antiddos-advanced.py
   ```

3. 在瀏覽器中輸入 `http://localhost:8080` 以訪問伺服器。


## 配置

可以通過修改以下變量來配置腳本的行為：

- `HTTP_PORT`：HTTP服務器的端口號。
- `IP_HTTP_THRESHOLD`：IP地址的HTTP請求閾值。如果一個IP地址的HTTP請求次數超過這個閾值，它就會被加入黑名單。
- `NODE_HTTP_THRESHOLD`：節點的HTTP請求閾值。如果一個IP地址對一個節點的HTTP請求次數超過這個閾值，它就會被加入黑名單。
- `SYN_THRESHOLD`：SYN Flag的閾值。如果一個IP地址發送的SYN Flag數量超過這個閾值，它就會被加入黑名單。
- `UDP_THRESHOLD`：UDP Flag的閾值。如果一個IP地址發送的UDP Flag數量超過這個閾值，它就會被加入黑名單。

## 功能說明

### AI學習

該腳本可以自動學習攻擊者的行為，並在需要時阻擋它們。它會記錄所有請求歷史，並在需要時進行清理。它還使用黑名單和白名單來控制訪問，並記錄所有HTTP請求。

### 檢測攻擊

該伺服器可以檢測並阻擋一些常見的攻擊，如HTTP Flood攻擊、SYN Flood攻擊、UDP Flood攻擊和DoS攻擊。

### 黑名單和白名單

該伺服器使用黑名單和白名單來控制訪問。您可以將IP地址添加到白名單中以允許訪問，也可以將IP地址添加到黑名單中以拒絕訪問。

## 注意事項

此腳本僅供參考，實際應用中需要根據需要進行修改和調整。它可能無法檢測所有攻擊。在實際應用中，您需要根據您的需求進行修改和調整。
