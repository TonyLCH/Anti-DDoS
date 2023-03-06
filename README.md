# 基於Python的Web伺服器

這是一個基於Python的Web伺服器，它可以檢測並阻擋一些常見的攻擊，如HTTP Flood攻擊、SYN Flood攻擊、UDP Flood攻擊和DoS攻擊。此外，它還具有自學習功能，可以自動學習攻擊者的行為，並在需要時阻擋它們。

## 系統需求

* Python 3.x
* 套接字(socket)庫
* 正則表達式(re)庫
* 日誌(logging)庫
* 線程(threading)庫

## 使用方法

1. 將腳本下載到本地。

2. 在命令行中運行以下命令以啟動伺服器：

   ```
   python advancedcc.py
   ```

3. 在瀏覽器中輸入 `http://localhost:8080` 以訪問伺服器。

## 功能說明

### 自學習

該伺服器可以自動學習攻擊者的行為，並在需要時阻擋它們。它會記錄所有請求歷史，並在需要時進行清理。它還使用黑名單和白名單來控制訪問，並記錄所有HTTP請求。

### 檢測攻擊

該伺服器可以檢測並阻擋一些常見的攻擊，如SYN Flood攻擊、UDP Flood攻擊和DoS攻擊。

### 黑名單和白名單

該伺服器使用黑名單和白名單來控制訪問。您可以將IP地址添加到白名單中以允許訪問，也可以將IP地址添加到黑名單中以拒絕訪問。

## 注意事項

此伺服器僅供參考，實際應用中需要根據需要進行修改和調整。它可能無法檢測所有攻擊，並且可能會導致一些假陽性或假陰性。在實際應用中，您需要根據您的需求進行修改和調整。
